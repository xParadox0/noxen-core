// Package depscan applies the dependency vulnerability policy of T0.09 to the
// JSON output of three scanners. It never runs a scanner: the Makefile target
// vuln-scan runs them and pipes their output in.
//
//   - govulncheck -json: a stream of concatenated JSON objects. A finding
//     blocks only at SYMBOL level (a vulnerable function is reachable);
//     PACKAGE and MODULE findings are warnings. govulncheck has no severity.
//   - pnpm audit --json: one JSON object. Severity high and critical block
//     (the constant threshold); an unknown severity string blocks too.
//   - trivy image --format json: HIGH and CRITICAL block; an unknown severity
//     string blocks.
//
// UNVERIFIED IMAGE SHAPE: no image and no Trivy exist on the host that wrote
// this package, so the Trivy parser (image.go) is written from knowledge of
// the documented output and its fixture testdata/image-scan-clean.json is
// SYNTHETIC. It is unverified against the real tool until the first image
// exists. The govulncheck and pnpm fixtures are trimmed real tool output.
//
// An allowlist (allowlist.go) waives findings by advisory ID or alias until
// the end of the expiry day (UTC). An expired entry is itself a finding.
// Every malformed input is an error, never a pass: the scan fails closed.
package depscan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxFailLines = 50
	maxWarnLines = 20
	maxClip      = 200
	// maxExpiredLines caps the expired-exception lines on their own, so a
	// stale waiver is never hidden behind a long list of findings.
	maxExpiredLines = 50
)

// maxInput is the input size cap. It is a variable only so a test can lower it.
var maxInput int64 = 256 << 20

// Entry is one allowlist exception.
type Entry struct {
	ID       string
	Reason   string
	Approver string
	Expires  time.Time // midnight UTC at the start of the last valid day
	Line     int
}

// expired reports whether the entry no longer waives at now: the last valid
// instant is the end of the Expires day, UTC.
func (e Entry) expired(now time.Time) bool {
	return !now.Before(e.Expires.AddDate(0, 0, 1))
}

// Report is the outcome of one scan. Blocking holds one description per
// blocking finding (without the "FAIL " prefix): the first Expired entries
// are the expired exceptions, the rest are the findings.
type Report struct {
	Scanner   string // "govulncheck", "pnpm" or "image"
	Blocking  []string
	Expired   int      // leading entries of Blocking that are expired exceptions
	Warnings  []string // full "warn ..." lines, sorted, at most maxWarnLines
	WarnTotal int
	Below     int // pnpm advisories below the threshold
	Waived    int // distinct advisory IDs waived by the allowlist
}

// Render returns the output lines of the report and whether the run failed.
// A failing run prints only the blocking lines and the total: the expired
// exceptions first (at most 50), then the findings (at most 50).
func (r Report) Render() ([]string, bool) {
	if n := len(r.Blocking); n > 0 {
		out := capLines(nil, r.Blocking[:r.Expired], maxExpiredLines, " expired exception(s)")
		out = capLines(out, r.Blocking[r.Expired:], maxFailLines, "")
		return append(out, fmt.Sprintf("FAIL %d blocking finding(s)", n)), true
	}
	ok := "OK " + r.Scanner
	switch r.Scanner {
	case "govulncheck":
		ok = fmt.Sprintf("OK govulncheck: 0 blocking, %d warning(s)", r.WarnTotal)
	case "pnpm":
		ok = fmt.Sprintf("OK pnpm audit: 0 blocking, %d below threshold", r.Below)
	case "image":
		ok = "OK image scan: 0 blocking"
	}
	if r.Waived > 0 {
		ok += fmt.Sprintf(", %d waived", r.Waived)
	}
	return append(append([]string(nil), r.Warnings...), ok), false
}

// capLines appends "FAIL " lines, at most limit of them, then a line that
// counts the rest.
func capLines(out, lines []string, limit int, noun string) []string {
	for i, l := range lines {
		if i == limit {
			return append(out, fmt.Sprintf("... and %d more%s", len(lines)-limit, noun))
		}
		out = append(out, "FAIL "+l)
	}
	return out
}

// Clip makes an input string safe to print: control characters become '?',
// and anything over 200 bytes is cut at a rune boundary and followed by an
// ellipsis and the original length.
func Clip(s string) string {
	n := len(s)
	if n > maxClip {
		i := maxClip
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		s = s[:i]
	}
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) || r == ' ' || r == ' ' {
			return '?'
		}
		return r
	}, s)
	if n > maxClip {
		s += fmt.Sprintf("…(%d bytes)", n)
	}
	return s
}

// policy is the allowlist evaluated at one instant.
type policy struct {
	live    map[string]bool
	expired []Entry
}

func newPolicy(allow []Entry, now time.Time) policy {
	p := policy{live: map[string]bool{}}
	for _, e := range allow {
		if e.expired(now) {
			p.expired = append(p.expired, e)
		} else {
			p.live[e.ID] = true
		}
	}
	return p
}

// waived reports whether any of the advisory identifiers has a live entry.
func (p policy) waived(ids ...string) bool {
	for _, id := range ids {
		if p.live[id] {
			return true
		}
	}
	return false
}

// item is one blocking finding with its sort key.
type item struct{ key, text string }

// finish sorts the blocking findings by key and stores them in the report
// after the expired exceptions (a stale waiver fails the run even when no
// finding mentions it, and is listed first so a long list of findings cannot
// hide it).
func (p policy) finish(rep *Report, items []item) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].key != items[j].key {
			return items[i].key < items[j].key
		}
		return items[i].text < items[j].text
	})
	exp := append([]Entry(nil), p.expired...)
	sort.SliceStable(exp, func(i, j int) bool { return exp[i].ID < exp[j].ID })
	for _, e := range exp {
		rep.Blocking = append(rep.Blocking,
			fmt.Sprintf("expired exception %s (expired %s)", Clip(e.ID), e.Expires.Format("2006-01-02")))
	}
	rep.Expired = len(exp)
	for _, it := range items {
		rep.Blocking = append(rep.Blocking, it.text)
	}
}

var (
	errEmpty     = errors.New("empty input")
	errTruncated = errors.New("input ends in the middle of a JSON value")
)

// capReader fails once more than maxInput bytes have been read.
type capReader struct {
	r io.Reader
	n int64
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > maxInput {
		return 0, fmt.Errorf("input larger than %d bytes", maxInput)
	}
	return n, err
}

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// openInput wraps r in a size cap and skips a UTF-8 byte order mark. It
// returns the number of bytes skipped, to keep reported offsets true.
func openInput(r io.Reader) (*bufio.Reader, int64) {
	br := bufio.NewReader(&capReader{r: r})
	if b, err := br.Peek(len(utf8BOM)); err == nil && bytes.Equal(b, utf8BOM) {
		_, _ = br.Discard(len(utf8BOM))
		return br, int64(len(utf8BOM))
	}
	return br, 0
}

// decodeErr maps decoder errors to the fail-closed messages.
func decodeErr(err error) error {
	switch {
	case errors.Is(err, io.EOF):
		return errEmpty
	case errors.Is(err, io.ErrUnexpectedEOF):
		return errTruncated
	}
	return err
}

// decodeOne reads one JSON document, rejects duplicate object keys at any
// depth (what names the input in that error), decodes exactly one value into
// v and rejects anything after it.
func decodeOne(r io.Reader, what string, v any) error {
	br, base := openInput(r)
	data, err := io.ReadAll(br)
	if err != nil {
		return wrapScan(what, decodeErr(err))
	}
	if err := checkKeys(data, base, what); err != nil {
		return wrapScan(what, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return wrapScan(what, decodeErr(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return wrapScan(what, errors.New("unexpected data after the JSON value"))
		}
		return wrapScan(what, decodeErr(err))
	}
	return nil
}
