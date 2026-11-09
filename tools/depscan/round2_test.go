package depscan

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var dupMsg = regexp.MustCompile(`^duplicate key in [a-z ]+ at byte offset [0-9]+$`)

// wantDup requires the duplicate-key error of the strict pre-pass: the fixed
// message, no echo of the key or the values, and no panic.
func wantDup(t *testing.T, fn scanFn, text string) {
	t.Helper()
	_, err := fn(strings.NewReader(text), nil, testNow)
	if err == nil {
		t.Fatal("want a duplicate key error, got a result")
	}
	if !dupMsg.MatchString(err.Error()) {
		t.Errorf("error %q is not \"duplicate key in <what> at byte offset <n>\"", err)
	}
	for _, leak := range []string{"SECRETKEY", "SECRETVALUE"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error echoes input: %v", err)
		}
	}
}

const pnpmHead = `{"advisories":{`

func TestDuplicateKeysPnpm(t *testing.T) {
	adv := func(sev string) string {
		return `"1":{"module_name":"m","github_advisory_id":"GHSA-1","patched_versions":">=1",` + sev + `}`
	}
	cases := map[string]string{
		"depth1":          `{"advisories":{},"advisories":{}}`,
		"depth3-verdict":  pnpmHead + adv(`"severity":"high","severity":"low"`) + `}}`,
		"depth3-low-high": pnpmHead + adv(`"severity":"low","severity":"high"`) + `}}`,
		"depth4":          `{"advisories":{"1":{"findings":[{"a":{"SECRETKEY":1,"SECRETKEY":2}}]}}}`,
		"array-element":   `{"advisories":{},"x":[{"k":1},{"SECRETKEY":"SECRETVALUE","SECRETKEY":2}]}`,
		"case-folded":     `{"advisories":{},"Advisories":{}}`,
		"case-folded-sev": pnpmHead + adv(`"severity":"high","Severity":"low"`) + `}}`,
		"unicode-folded":  `{"advisories":{},"xK":1,"xk":2}`,
		"escaped-equal":   `{"advisories":{},"a":1,"a":2}`,
		"after-value":     `{"advisories":{},"k":{"a":1},"k":{"a":1}}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) { wantDup(t, pnpm, text) })
	}
}

func TestDuplicateKeysImage(t *testing.T) {
	vuln := func(sev string) string {
		return `{"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1",` + sev + `}`
	}
	cases := map[string]string{
		"depth1-verdict": `{"Results":[{"Target":"t","Vulnerabilities":[` + vuln(`"Severity":"HIGH"`) + `]}],"Results":[]}`,
		"depth1-empty":   `{"Results":[],"Results":[]}`,
		"depth4":         `{"Results":[{"Target":"t","Vulnerabilities":[` + vuln(`"Severity":"HIGH","Severity":"LOW"`) + `]}]}`,
		"array-element":  `{"Results":[{"Target":"a","Target":"b"}]}`,
		"second-element": `{"Results":[{"Target":"a"},{"Target":"b","Vulnerabilities":[],"Vulnerabilities":[]}]}`,
		"case-folded":    `{"Results":[],"results":[]}`,
		"case-folded-in": `{"Results":[{"Target":"t","target":"u"}]}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) { wantDup(t, image, text) })
	}
}

func TestDuplicateKeysGovulncheck(t *testing.T) {
	cases := map[string]string{
		"config-depth2":    `{"config":{"scanner_name":"a","scanner_name":"b"}}` + "\n" + cfg,
		"config-case":      `{"config":{},"Config":{}}` + "\n" + cfg,
		"progress-in-tail": cfg + `{"progress":{"message":"x","message":"y"}}` + "\n",
		"finding-depth1":   cfg + `{"finding":{"osv":"GO-1","trace":[{"module":"m","version":"v1"}]},"finding":null}` + "\n",
		"trace-element":    cfg + `{"finding":{"osv":"GO-1","trace":[{"module":"m","function":"F","function":null}]}}` + "\n",
		"osv-case":         cfg + `{"osv":{"id":"GO-1","ID":"GO-2"}}` + "\n",
		"sbom-nested":      cfg + `{"SBOM":{"modules":[{"path":"a","SECRETKEY":1,"SECRETKEY":2}]}}` + "\n",
		"second-message":   cfg + findingMsg("GO-1", "v1", `{"module":"m","version":"v1"}`) + `{"osv":{"id":"GO-2","id":"GO-3"}}` + "\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) { wantDup(t, govulncheck, text) })
	}
}

func TestDuplicateKeysHugeKey(t *testing.T) {
	huge := strings.Repeat("K", 1_000_000)
	t.Run("equal-huge-keys", func(t *testing.T) {
		wantDup(t, pnpm, `{"advisories":{},"`+huge+`":1,"`+huge+`":2}`)
	})
	t.Run("huge-keys-differ-at-end", func(t *testing.T) {
		text := `{"advisories":{},"` + huge + `a":1,"` + huge + `b":2}`
		if _, err := Pnpm(strings.NewReader(text), nil, testNow); err != nil {
			t.Fatalf("distinct keys rejected: %v", err)
		}
	})
	t.Run("many-keys-no-duplicate", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(`{"advisories":{}`)
		for i := 0; i < 20000; i++ {
			fmt.Fprintf(&b, `,"k%d":{"a":1}`, i)
		}
		b.WriteString(`}`)
		if _, err := Pnpm(strings.NewReader(b.String()), nil, testNow); err != nil {
			t.Fatalf("distinct keys rejected: %v", err)
		}
	})
}

// The same key in different objects, or in elements of one array, is normal.
func TestSameKeyInDifferentObjectsIsFine(t *testing.T) {
	text := `{"advisories":{"1":{"severity":"low","module_name":"m"},"2":{"severity":"low","module_name":"m"}},` +
		`"x":[{"k":1},{"k":2}],"y":{"k":1},"z":{"k":{"k":1}}}`
	rep, err := Pnpm(strings.NewReader(text), nil, testNow)
	if err != nil || rep.Below != 2 {
		t.Fatalf("below=%d err=%v", rep.Below, err)
	}
}

func TestDuplicateKeyAfterBOMAndCRLF(t *testing.T) {
	text := "\xef\xbb\xbf" + "{\r\n \"Results\": [],\r\n \"Results\": []\r\n}"
	wantDup(t, image, text)
}

func TestApprover(t *testing.T) {
	item := func(approver string) string {
		return "entries:\n  - id: GO-2024-2687\n    reason: r\n    approver: " + approver + "\n    expires: 2026-12-31\n"
	}
	bad := map[string]string{
		"Mallory":      `Mallory`,
		"lower":        `sol`,
		"upper":        `SOL`,
		"quoted-lower": `"sol"`,
		"leading-sp":   `" Sol"`,
		"trailing-sp":  `"Sol "`,
		"reviewer":     `Sol Reviewer`,
		"prefix":       `Solomon`,
		"quoted-multi": `"Sol Reviewer"`,
		"secret":       `SECRETVALUE`,
	}
	for name, v := range bad {
		t.Run("reject/"+name, func(t *testing.T) {
			_, err := ParseAllowlist([]byte(item(v)))
			if err == nil {
				t.Fatal("want error: only the approver Sol is accepted")
			}
			if !strings.Contains(err.Error(), "line 4") {
				t.Errorf("error %q does not name line 4", err)
			}
			if strings.Contains(err.Error(), "SECRETVALUE") || strings.Contains(err.Error(), "Mallory") {
				t.Errorf("error echoes the approver: %v", err)
			}
		})
	}
	for name, v := range map[string]string{"plain": `Sol`, "quoted": `"Sol"`, "plain-leading-ws": ` Sol`, "plain-trailing-ws": `Sol `} {
		t.Run("accept/"+name, func(t *testing.T) {
			a, err := ParseAllowlist([]byte(item(v)))
			if err != nil || len(a) != 1 || a[0].Approver != "Sol" {
				t.Fatalf("entries=%v err=%v", a, err)
			}
		})
	}
}

func TestRealAllowlistStatesParserEnforcesSol(t *testing.T) {
	b, err := readFile("allowlist.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "parser enforces") {
		t.Error("allowlist.yaml must say that the parser enforces the Sol approver")
	}
}

const (
	sbomMsg   = `{"SBOM":{"go_version":"go1.27.3","modules":[{"path":"m"}],"roots":["m"]}}` + "\n"
	progMsg   = `{"progress":{"message":"p"}}` + "\n"
	incomplet = "govulncheck stream incomplete (the scan did not reach the check phase)"
)

func TestGovulncheckIncompleteStream(t *testing.T) {
	clean := fixture(t, "govulncheck-clean.json")
	cases := map[string]string{
		"after-config":           cfgOnly,
		"after-sbom":             cfgOnly + sbomMsg,
		"after-first-progress":   cfgOnly + sbomMsg + progMsg,
		"after-osv":              cfgOnly + sbomMsg + progMsg + osvMsg("GO-2025-0001"),
		"fixture-after-config":   clean[:270],
		"fixture-after-progress": clean[:353],
		"config-trailing-nl":     clean[:271],
		"one-progress-only":      cfgOnly + progMsg,
		"three-messages-no-prog": cfgOnly + sbomMsg + osvMsg("GO-1"),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Govulncheck(strings.NewReader(text), nil, testNow)
			if err == nil {
				t.Fatal("want error: the stream stops before the check phase")
			}
			if err.Error() != incomplet {
				t.Errorf("error = %q, want %q", err, incomplet)
			}
		})
	}
}

func TestGovulncheckCompleteStreams(t *testing.T) {
	cases := map[string]string{
		"fixture":            fixture(t, "govulncheck-clean.json"),
		"with-sbom-and-osv":  cfgOnly + sbomMsg + progMsg + osvMsg("GO-2025-0001") + progMsg,
		"progress-any-text":  cfgOnly + `{"progress":{}}` + "\n" + `{"progress":{"message":"changed wording"}}` + "\n",
		"progress-first":     progMsg + progMsg + cfgOnly,
		"three-progress":     cfgOnly + progMsg + progMsg + progMsg,
		"findings-after-two": cfg + findingMsg("GO-1", "v1", `{"module":"m","version":"v1"}`),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			lines, failed := run(t, govulncheck, text, nil)
			if failed {
				t.Fatalf("complete stream failed: %q", lines)
			}
		})
	}
}

func TestExpiredExceptionsPrintFirst(t *testing.T) {
	var many strings.Builder
	many.WriteString(cfg)
	for i := 0; i < 60; i++ {
		many.WriteString(findingMsg(fmt.Sprintf("GO-2025-%04d", i), "v1",
			fmt.Sprintf(`{"module":"m%d","version":"v1","package":"p","function":"F"}`, i)))
	}
	a := allowlist(t, "entries:\n  - id: GO-9999-0001\n    reason: r\n    approver: Sol\n    expires: 2026-01-31\n")
	lines, failed := run(t, govulncheck, many.String(), a)
	if !failed {
		t.Fatal("want failure")
	}
	if lines[0] != "FAIL expired exception GO-9999-0001 (expired 2026-01-31)" {
		t.Errorf("first line = %q, want the expired exception", lines[0])
	}
	findings := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "FAIL govulncheck ") {
			findings++
		}
	}
	if findings != 50 {
		t.Errorf("finding lines = %d, want 50", findings)
	}
	wantLine(t, lines, "... and 10 more")
	if last(lines) != "FAIL 61 blocking finding(s)" {
		t.Errorf("last line = %q", last(lines))
	}
}

func TestExpiredExceptionsHaveTheirOwnCap(t *testing.T) {
	var list strings.Builder
	list.WriteString("entries:\n")
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&list, "  - id: GO-9999-%04d\n    reason: r\n    approver: Sol\n    expires: 2026-01-31\n", i)
	}
	a := allowlist(t, list.String())
	lines, failed := run(t, govulncheck, cfg, a)
	if !failed {
		t.Fatal("want failure")
	}
	expired := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "FAIL expired exception ") {
			expired++
		}
	}
	if expired != 50 {
		t.Errorf("expired lines = %d, want 50", expired)
	}
	wantLine(t, lines, "... and 10 more expired exception(s)")
	if last(lines) != "FAIL 60 blocking finding(s)" {
		t.Errorf("last line = %q", last(lines))
	}
}

func TestExpiredFirstThenFindingsInOrder(t *testing.T) {
	s := cfg + findingMsg("GO-2025-0001", "v1", `{"module":"m","version":"v1","package":"p","function":"F"}`)
	a := allowlist(t, "entries:\n  - id: GO-9999-0001\n    reason: r\n    approver: Sol\n    expires: 2026-01-31\n")
	lines, _ := run(t, govulncheck, s, a)
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "FAIL expired exception ") ||
		!strings.HasPrefix(lines[1], "FAIL govulncheck GO-2025-0001") || lines[2] != "FAIL 2 blocking finding(s)" {
		t.Fatalf("lines = %q", lines)
	}
}
