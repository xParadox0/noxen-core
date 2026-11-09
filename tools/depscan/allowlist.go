package depscan

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxAllowlistBytes = 1 << 20
	maxAllowlistLine  = 1000
)

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	datePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	entryKeys   = []string{"id", "reason", "approver", "expires"}
)

// approver is the only identity that may approve an exception.
const approver = "Sol"

// ParseAllowlist parses the one accepted shape of allowlist.yaml:
//
//	# comment
//	entries:
//	  - id: GO-2024-2687
//	    reason: short text
//	    approver: Sol
//	    expires: 2026-12-31
//
// The decoded scalar value of approver must equal exactly Sol, case-sensitive
// (surrounding YAML whitespace and double quotes are removed before the
// comparison). An empty file and "entries: []" are empty allowlists. Anything
// else is an error that names only the line number, never the content. This is not a
// YAML parser: no anchors, tags, flow style, block scalars, single quotes,
// escapes, inline comments or tabs. Values are single-line plain scalars or
// double-quoted without escapes. expires is YYYY-MM-DD, valid through the
// end of that day, UTC.
func ParseAllowlist(data []byte) ([]Entry, error) {
	if len(data) > maxAllowlistBytes {
		return nil, fmt.Errorf("allowlist larger than %d bytes", maxAllowlistBytes)
	}
	data = bytes.TrimPrefix(data, utf8BOM)
	p := allowParser{ids: map[string]bool{}}
	for i, line := range strings.Split(string(data), "\n") {
		if err := p.line(i+1, strings.TrimSuffix(line, "\r")); err != nil {
			return nil, err
		}
	}
	return p.finish()
}

type allowParser struct {
	state   int // 0 before entries, 1 inside the list, 2 after "entries: []"
	listAt  int
	entries []Entry
	cur     *Entry
	seen    map[string]bool
	ids     map[string]bool
}

func lineErr(n int, msg string) error { return fmt.Errorf("allowlist line %d: %s", n, msg) }

func (p *allowParser) line(n int, line string) error {
	if len(line) > maxAllowlistLine {
		return lineErr(n, "line too long")
	}
	if !utf8.ValidString(line) {
		return lineErr(n, "invalid UTF-8")
	}
	for _, r := range line {
		switch {
		case r == '\t':
			return lineErr(n, "tab character")
		case r < 0x20 || r == 0x7f:
			return lineErr(n, "control character")
		}
	}
	text := strings.TrimRight(line, " ")
	if text == "" || strings.HasPrefix(strings.TrimLeft(text, " "), "#") {
		return nil
	}
	switch p.state {
	case 0:
		switch text {
		case "entries:":
			p.state, p.listAt = 1, n
		case "entries: []":
			p.state = 2
		default:
			return lineErr(n, "expected \"entries:\"")
		}
		return nil
	case 2:
		return lineErr(n, "content after \"entries: []\"")
	}
	var kv string
	switch {
	case strings.HasPrefix(text, "  - "):
		if err := p.closeItem(); err != nil {
			return err
		}
		p.cur = &Entry{Line: n}
		p.seen = map[string]bool{}
		kv = text[4:]
	case strings.HasPrefix(text, "    ") && p.cur != nil:
		kv = text[4:]
	default:
		return lineErr(n, "unexpected line or indentation")
	}
	if strings.HasPrefix(kv, " ") {
		return lineErr(n, "unexpected indentation")
	}
	return p.keyValue(n, kv)
}

func (p *allowParser) keyValue(n int, kv string) error {
	i := strings.IndexByte(kv, ':')
	if i < 0 {
		return lineErr(n, "expected key: value")
	}
	key, rest := kv[:i], kv[i+1:]
	known := false
	for _, k := range entryKeys {
		known = known || k == key
	}
	if !known {
		return lineErr(n, "unknown key")
	}
	if p.seen[key] {
		return lineErr(n, "duplicate key")
	}
	p.seen[key] = true
	if rest == "" || rest[0] != ' ' {
		return lineErr(n, "expected a value after the colon and a space")
	}
	val, ok := scalar(strings.TrimLeft(rest, " "))
	if !ok {
		return lineErr(n, "value is not a single-line plain or double-quoted scalar")
	}
	switch key {
	case "id":
		if !idPattern.MatchString(val) {
			return lineErr(n, "invalid id")
		}
		if p.ids[val] {
			return lineErr(n, "duplicate id")
		}
		p.ids[val] = true
		p.cur.ID = val
	case "reason":
		p.cur.Reason = val
	case "approver":
		if val != approver {
			return lineErr(n, "approver must be Sol")
		}
		p.cur.Approver = val
	case "expires":
		d, err := time.Parse("2006-01-02", val)
		if err != nil || !datePattern.MatchString(val) {
			return lineErr(n, "expires is not a YYYY-MM-DD date")
		}
		p.cur.Expires = d
	}
	return nil
}

// scalar returns the value of a plain or double-quoted single-line scalar.
func scalar(v string) (string, bool) {
	if v == "" {
		return "", false
	}
	if v[0] == '"' {
		if len(v) < 3 || v[len(v)-1] != '"' {
			return "", false
		}
		inner := v[1 : len(v)-1]
		if strings.ContainsAny(inner, "\"\\") {
			return "", false
		}
		return inner, true
	}
	if strings.ContainsRune("&*!|>[]{}%@`'#,?", rune(v[0])) || v == "-" || strings.HasPrefix(v, "- ") {
		return "", false
	}
	if strings.Contains(v, " #") || strings.Contains(v, ": ") || strings.HasSuffix(v, ":") {
		return "", false
	}
	return v, true
}

func (p *allowParser) closeItem() error {
	if p.cur == nil {
		return nil
	}
	for _, k := range entryKeys {
		if !p.seen[k] {
			return lineErr(p.cur.Line, "entry is missing a key (id, reason, approver and expires are all required)")
		}
	}
	p.entries = append(p.entries, *p.cur)
	p.cur = nil
	return nil
}

func (p *allowParser) finish() ([]Entry, error) {
	if err := p.closeItem(); err != nil {
		return nil, err
	}
	if p.state == 1 && len(p.entries) == 0 {
		return nil, lineErr(p.listAt, "\"entries:\" has no items (write \"entries: []\" for none)")
	}
	return p.entries, nil
}
