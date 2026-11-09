package depscan

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

type pnpmDoc struct {
	Advisories *map[string]pnpmAdvisory `json:"advisories"`
}

type pnpmAdvisory struct {
	ModuleName        string `json:"module_name"`
	PatchedVersions   string `json:"patched_versions"`
	Severity          string `json:"severity"`
	GithubAdvisoryID  string `json:"github_advisory_id"`
	VulnerableVersion string `json:"vulnerable_versions"`
}

// Pnpm applies the policy to pnpm audit --json output: advisories at or
// above the threshold, and advisories of unknown severity, block unless
// waived by their GHSA id; the rest are counted as below threshold.
func Pnpm(r io.Reader, allow []Entry, now time.Time) (Report, error) {
	var doc pnpmDoc
	if err := decodeOne(r, "pnpm audit output", &doc); err != nil {
		return Report{}, err
	}
	if doc.Advisories == nil {
		return Report{}, errors.New("pnpm audit output: no advisories object (error output, or not pnpm audit --json)")
	}
	pol := newPolicy(allow, now)
	rep := Report{Scanner: "pnpm"}
	var items []item
	waivedIDs := map[string]bool{}
	for key, a := range *doc.Advisories {
		id := a.GithubAdvisoryID
		if id == "" {
			id = "pnpm-" + key
		}
		sev, known := pnpmSeverity[a.Severity]
		if known && sev < threshold {
			rep.Below++
			continue
		}
		if pol.waived(id) {
			waivedIDs[id] = true
			continue
		}
		var text string
		if known {
			text = fmt.Sprintf("pnpm %s %s %s patched %s", Clip(id), Clip(a.ModuleName), a.Severity, Clip(a.PatchedVersions))
		} else {
			text = fmt.Sprintf("pnpm %s %s unknown severity %q", Clip(id), Clip(a.ModuleName), Clip(a.Severity))
		}
		items = append(items, item{key: id + "\x00" + a.ModuleName, text: text})
	}
	rep.Waived = len(waivedIDs)
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
	pol.finish(&rep, items)
	return rep, nil
}
