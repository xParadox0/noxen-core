package depscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

// Finding levels, from the weakest: a trace with a function frame is SYMBOL,
// one whose deepest frame is a package is PACKAGE, otherwise MODULE.
const (
	levelModule  = "MODULE"
	levelPackage = "PACKAGE"
	levelSymbol  = "SYMBOL"
)

type gvMessage struct {
	Config   *struct{}  `json:"config"`
	Progress *struct{}  `json:"progress"`
	SBOM     *struct{}  `json:"SBOM"`
	OSV      *gvOSV     `json:"osv"`
	Finding  *gvFinding `json:"finding"`
}

type gvOSV struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type gvFinding struct {
	OSV          string    `json:"osv"`
	FixedVersion string    `json:"fixed_version"`
	Trace        []gvFrame `json:"trace"`
}

type gvFrame struct {
	Module   string  `json:"module"`
	Version  string  `json:"version"`
	Package  string  `json:"package"`
	Function *string `json:"function"`
	Receiver string  `json:"receiver"`
}

// level classifies a trace.
func (f gvFinding) level() string {
	lvl := levelModule
	for _, fr := range f.Trace {
		if fr.Function != nil {
			return levelSymbol
		}
		if fr.Package != "" {
			lvl = levelPackage
		}
	}
	return lvl
}

// warning is the best non-symbol finding seen for one advisory ID.
type warning struct {
	level  string
	module string
	ver    string
}

// minProgress is the number of progress messages a stream that reached the
// check phase has: "fetching the database" and "checking the code".
const minProgress = 2

// Govulncheck applies the policy to a govulncheck -json stream: every SYMBOL
// finding blocks unless waived; PACKAGE and MODULE findings only warn.
//
// Each message is checked for duplicate object keys before it is decoded.
// The stream has no end marker. Real govulncheck emits, in order: config,
// SBOM, a progress message, the osv messages, a second progress message, then
// the finding messages. A stream is complete enough only if it holds a config
// message and at least two progress messages (counted by message type, not by
// text), which rejects every cut before the check phase.
//
// KNOWN LIMIT: a stream cut inside the finding phase, at a message boundary,
// looks like a complete stream with fewer findings, and this parser cannot
// tell. The completion evidence is govulncheck's exit status, which the
// Makefile target vuln-scan requires to be 0 before it calls this parser.
func Govulncheck(r io.Reader, allow []Entry, now time.Time) (Report, error) {
	br, base := openInput(r)
	dec := json.NewDecoder(br)
	var (
		sawConfig bool
		progress  int
		aliases   = map[string][]string{}
		findings  []gvFinding
	)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return Report{}, fmt.Errorf("govulncheck stream: %w", decodeErr(err))
		}
		if err := checkKeys(raw, base+dec.InputOffset()-int64(len(raw)), "govulncheck message"); err != nil {
			return Report{}, wrapScan("govulncheck stream", err)
		}
		var m gvMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return Report{}, fmt.Errorf("govulncheck stream: %w", decodeErr(err))
		}
		switch {
		case m.Config != nil:
			sawConfig = true
		case m.Progress != nil:
			progress++
		case m.SBOM != nil:
		case m.OSV != nil:
			if m.OSV.ID == "" {
				return Report{}, errors.New("govulncheck stream: osv message without id")
			}
			aliases[m.OSV.ID] = append(aliases[m.OSV.ID], m.OSV.Aliases...)
		case m.Finding != nil:
			if m.Finding.OSV == "" || len(m.Finding.Trace) == 0 {
				return Report{}, errors.New("govulncheck stream: finding without osv id or trace")
			}
			findings = append(findings, *m.Finding)
		default:
			return Report{}, errors.New("govulncheck stream: unrecognized message")
		}
	}
	if !sawConfig {
		return Report{}, errors.New("govulncheck stream: no config message (empty or not govulncheck -json output)")
	}

	if progress < minProgress {
		return Report{}, errors.New("govulncheck stream incomplete (the scan did not reach the check phase)")
	}

	pol := newPolicy(allow, now)
	rep := Report{Scanner: "govulncheck"}
	var items []item
	seen := map[string]bool{}
	symbolIDs := map[string]bool{}
	waivedIDs := map[string]bool{}
	warns := map[string]warning{}
	for _, f := range findings {
		lvl := f.level()
		if lvl == levelSymbol {
			symbolIDs[f.OSV] = true
			if pol.waived(append([]string{f.OSV}, aliases[f.OSV]...)...) {
				waivedIDs[f.OSV] = true
				continue
			}
			it := symbolItem(f)
			if !seen[it.text] {
				seen[it.text] = true
				items = append(items, it)
			}
			continue
		}
		w, ok := warns[f.OSV]
		if !ok || (lvl == levelPackage && w.level == levelModule) {
			warns[f.OSV] = warning{lvl, f.Trace[0].Module, f.Trace[0].Version}
		}
	}
	rep.Waived = len(waivedIDs)

	var ids []string
	for id := range warns {
		if !symbolIDs[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	rep.WarnTotal = len(ids)
	for i, id := range ids {
		if i == maxWarnLines {
			break
		}
		w := warns[id]
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("warn %s %s@%s (%s)", Clip(id), Clip(w.module), Clip(w.ver), w.level))
	}
	pol.finish(&rep, items)
	return rep, nil
}

// symbolItem describes a SYMBOL finding: advisory, vulnerable module and
// version (the first trace frame), fixed version and the first function.
func symbolItem(f gvFinding) item {
	first := f.Trace[0]
	fn := ""
	for _, fr := range f.Trace {
		if fr.Function == nil {
			continue
		}
		fn = *fr.Function
		if fr.Receiver != "" {
			fn = "(" + Clip(fr.Receiver) + ")." + Clip(fn)
		} else {
			fn = Clip(fn)
		}
		if fr.Package != "" {
			fn = Clip(fr.Package) + "." + fn
		}
		break
	}
	fixed := f.FixedVersion
	if fixed == "" {
		fixed = "none"
	}
	text := fmt.Sprintf("govulncheck %s %s@%s fixed %s %s",
		Clip(f.OSV), Clip(first.Module), Clip(first.Version), Clip(fixed), fn)
	return item{key: f.OSV, text: text}
}
