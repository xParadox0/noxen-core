package depscan

import (
	"errors"
	"fmt"
	"io"
	"time"
)

// The Trivy shape below is written from knowledge of `trivy image --format
// json`, not from a real run: it is unverified against the real tool until
// the first image exists (see the package comment).

type trivyOutput struct {
	Results *[]trivyTarget `json:"Results"`
}

type trivyTarget struct {
	Target          string         `json:"Target"`
	Vulnerabilities []trivyFinding `json:"Vulnerabilities"`
}

type trivyFinding struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
}

// Image applies the policy to trivy image --format json output: HIGH and
// CRITICAL, and any severity string outside Trivy's list, block unless
// waived by the vulnerability ID.
func Image(r io.Reader, allow []Entry, now time.Time) (Report, error) {
	var doc trivyOutput
	if err := decodeOne(r, "image scan output", &doc); err != nil {
		return Report{}, err
	}
	if doc.Results == nil {
		return Report{}, errors.New("image scan output: no Results array (not trivy image --format json output)")
	}
	pol := newPolicy(allow, now)
	rep := Report{Scanner: "image"}
	var items []item
	waivedIDs := map[string]bool{}
	for _, res := range *doc.Results {
		for _, v := range res.Vulnerabilities {
			sev, known := trivySeverity[v.Severity]
			if known && sev < threshold {
				continue
			}
			if pol.waived(v.VulnerabilityID) {
				waivedIDs[v.VulnerabilityID] = true
				continue
			}
			pkg := fmt.Sprintf("%s@%s", Clip(v.PkgName), Clip(v.InstalledVersion))
			var text string
			if known {
				fixed := v.FixedVersion
				if fixed == "" {
					fixed = "none"
				}
				text = fmt.Sprintf("image %s %s %s fixed %s (%s)", Clip(v.VulnerabilityID), pkg, v.Severity, Clip(fixed), Clip(res.Target))
			} else {
				text = fmt.Sprintf("image %s %s unknown severity %q (%s)", Clip(v.VulnerabilityID), pkg, Clip(v.Severity), Clip(res.Target))
			}
			items = append(items, item{key: v.VulnerabilityID + "\x00" + res.Target + "\x00" + pkg, text: text})
		}
	}
	rep.Waived = len(waivedIDs)
	pol.finish(&rep, items)
	return rep, nil
}
