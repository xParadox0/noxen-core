package depscan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testNow is the injected clock of every test.
var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// scanFn is the common shape of the three parsers.
type scanFn func(r *strings.Reader, allow []Entry, now time.Time) (Report, error)

func govulncheck(r *strings.Reader, a []Entry, n time.Time) (Report, error) {
	return Govulncheck(r, a, n)
}
func pnpm(r *strings.Reader, a []Entry, n time.Time) (Report, error)  { return Pnpm(r, a, n) }
func image(r *strings.Reader, a []Entry, n time.Time) (Report, error) { return Image(r, a, n) }

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

func allowlist(t *testing.T, text string) []Entry {
	t.Helper()
	a, err := ParseAllowlist([]byte(text))
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	return a
}

// run applies fn to text and renders the result.
func run(t *testing.T, fn scanFn, text string, allow []Entry) ([]string, bool) {
	t.Helper()
	rep, err := fn(strings.NewReader(text), allow, testNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return rep.Render()
}

func wantLine(t *testing.T, lines []string, want string) {
	t.Helper()
	for _, l := range lines {
		if l == want {
			return
		}
	}
	t.Errorf("missing line %q in:\n%s", want, strings.Join(lines, "\n"))
}

func wantContains(t *testing.T, lines []string, parts ...string) {
	t.Helper()
	for _, l := range lines {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(l, p)
		}
		if ok {
			return
		}
	}
	t.Errorf("no line contains %q in:\n%s", parts, strings.Join(lines, "\n"))
}

func last(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

func TestDepscan(t *testing.T) {
	t.Run("govulncheck-high", func(t *testing.T) {
		lines, failed := run(t, govulncheck, fixture(t, "govulncheck-high.json"), nil)
		if !failed {
			t.Fatalf("want failure, got pass:\n%s", strings.Join(lines, "\n"))
		}
		wantContains(t, lines, "FAIL govulncheck GO-2026-6617", "golang.org/x/net@v0.17.0", "fixed v0.60.0", "Read")
		if last(lines) != "FAIL 1 blocking finding(s)" {
			t.Errorf("last line = %q", last(lines))
		}
		for _, l := range lines {
			if strings.HasPrefix(l, "warn ") || strings.HasPrefix(l, "OK ") {
				t.Errorf("failing run printed %q", l)
			}
		}
	})
	t.Run("pnpm-audit-critical", func(t *testing.T) {
		lines, failed := run(t, pnpm, fixture(t, "pnpm-audit-critical.json"), nil)
		if !failed {
			t.Fatalf("want failure, got pass")
		}
		wantLine(t, lines, "FAIL pnpm GHSA-35jh-r3h4-6jhm lodash critical patched >=4.17.21")
		wantLine(t, lines, "FAIL pnpm GHSA-p6mc-m468-83gw lodash critical patched >=4.17.19")
		if last(lines) != "FAIL 2 blocking finding(s)" {
			t.Errorf("last line = %q", last(lines))
		}
	})
	t.Run("image-scan-clean", func(t *testing.T) {
		lines, failed := run(t, image, fixture(t, "image-scan-clean.json"), nil)
		if failed || len(lines) != 1 || lines[0] != "OK image scan: 0 blocking" {
			t.Fatalf("failed=%v lines=%q", failed, lines)
		}
	})
	t.Run("expired-exception", func(t *testing.T) {
		a := allowlist(t, fixture(t, "expired-exception.yaml"))
		lines, failed := run(t, govulncheck, fixture(t, "expired-exception.json"), a)
		if !failed {
			t.Fatalf("want failure, got pass:\n%s", strings.Join(lines, "\n"))
		}
		wantLine(t, lines, "FAIL expired exception GO-2024-0001 (expired 2026-01-31)")
		if last(lines) != "FAIL 1 blocking finding(s)" {
			t.Errorf("last line = %q", last(lines))
		}
	})
}

func TestGovulncheckClean(t *testing.T) {
	lines, failed := run(t, govulncheck, fixture(t, "govulncheck-clean.json"), nil)
	if failed || len(lines) != 1 || lines[0] != "OK govulncheck: 0 blocking, 0 warning(s)" {
		t.Fatalf("failed=%v lines=%q", failed, lines)
	}
}

func TestGovulncheckWarningsOnly(t *testing.T) {
	// The real sample reports GO-2024-2687 at module and package level only.
	lines, failed := run(t, govulncheck, fixture(t, "govulncheck-warn.json"), nil)
	if failed {
		t.Fatalf("warnings must not fail:\n%s", strings.Join(lines, "\n"))
	}
	want := []string{
		"warn GO-2024-2687 golang.org/x/net@v0.17.0 (PACKAGE)",
		"OK govulncheck: 0 blocking, 1 warning(s)",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines =\n%s", strings.Join(lines, "\n"))
	}
}

func TestGovulncheckModuleLevelWarning(t *testing.T) {
	stream := osvMsg("GO-2025-1111") + findingMsg("GO-2025-1111", "v1.2.3", `{"module":"example.com/m","version":"v1.0.0"}`)
	stream = cfg + stream
	lines, failed := run(t, govulncheck, stream, nil)
	if failed {
		t.Fatalf("module level must not fail")
	}
	wantLine(t, lines, "warn GO-2025-1111 example.com/m@v1.0.0 (MODULE)")
	wantLine(t, lines, "OK govulncheck: 0 blocking, 1 warning(s)")
}

func TestGovulncheckHighWithAllowlists(t *testing.T) {
	high := fixture(t, "govulncheck-high.json")
	cases := []struct {
		name, list string
		now        time.Time
		fail       bool
	}{
		{"by-id", "GO-2026-6617", testNow, false},
		{"by-alias", "CVE-2026-97032", testNow, false},
		{"other-id", "GO-2024-2687", testNow, true},
		{"expired-id", "GO-2026-6617", time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"last-second", "GO-2026-6617", time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := allowlist(t, "entries:\n  - id: "+c.list+"\n    reason: r\n    approver: Sol\n    expires: 2026-12-31\n")
			rep, err := Govulncheck(strings.NewReader(high), a, c.now)
			if err != nil {
				t.Fatal(err)
			}
			lines, failed := rep.Render()
			if failed != c.fail {
				t.Fatalf("failed=%v want %v:\n%s", failed, c.fail, strings.Join(lines, "\n"))
			}
			if !c.fail {
				wantLine(t, lines, "OK govulncheck: 0 blocking, 1 warning(s), 1 waived")
			}
		})
	}
}

func TestExpiredExceptionAlsoFailsMatchingFinding(t *testing.T) {
	a := allowlist(t, "entries:\n  - id: GO-2026-6617\n    reason: r\n    approver: Sol\n    expires: 2026-05-31\n")
	lines, failed := run(t, govulncheck, fixture(t, "govulncheck-high.json"), a)
	if !failed {
		t.Fatal("want failure")
	}
	wantContains(t, lines, "FAIL govulncheck GO-2026-6617")
	wantLine(t, lines, "FAIL expired exception GO-2026-6617 (expired 2026-05-31)")
	if last(lines) != "FAIL 2 blocking finding(s)" {
		t.Errorf("last line = %q", last(lines))
	}
}

func TestGovulncheckDeterministicOrder(t *testing.T) {
	var ids = []string{"GO-2025-0003", "GO-2025-0001", "GO-2025-0002"}
	build := func(order []int) string {
		s := cfg
		for _, i := range order {
			s += findingMsg(ids[i], "v1", `{"module":"m/`+ids[i]+`","version":"v0.1.0","package":"m/p","function":"F"}`)
			s += findingMsg(ids[i]+"-W", "v1", `{"module":"w/`+ids[i]+`","version":"v0.1.0"}`)
		}
		return s
	}
	a, _ := run(t, govulncheck, build([]int{0, 1, 2}), nil)
	b, _ := run(t, govulncheck, build([]int{2, 0, 1}), nil)
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatalf("order depends on input:\n%s\n--\n%s", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
	if len(a) < 3 || !strings.Contains(a[0], "GO-2025-0001") || !strings.Contains(a[1], "GO-2025-0002") || !strings.Contains(a[2], "GO-2025-0003") {
		t.Fatalf("not sorted by ID:\n%s", strings.Join(a, "\n"))
	}
}

func TestGovulncheckWarningCap(t *testing.T) {
	s := cfg
	for i := 0; i < 30; i++ {
		s += findingMsg(fmt.Sprintf("GO-2025-%04d", i), "v1", fmt.Sprintf(`{"module":"m%d","version":"v1.0.0"}`, i))
	}
	lines, failed := run(t, govulncheck, s, nil)
	if failed {
		t.Fatal("warnings must not fail")
	}
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "warn ") {
			n++
		}
	}
	if n != 20 {
		t.Errorf("warn lines = %d, want 20", n)
	}
	wantLine(t, lines, "OK govulncheck: 0 blocking, 30 warning(s)")
}

func TestGovulncheckOnePerAdvisoryAtHighestLevel(t *testing.T) {
	s := cfg +
		findingMsg("GO-2025-0009", "v1", `{"module":"m","version":"v1.0.0"}`) +
		findingMsg("GO-2025-0009", "v1", `{"module":"m","version":"v1.0.0","package":"m/p"}`) +
		findingMsg("GO-2025-0009", "v1", `{"module":"m","version":"v1.0.0"}`)
	lines, _ := run(t, govulncheck, s, nil)
	if len(lines) != 2 || lines[0] != "warn GO-2025-0009 m@v1.0.0 (PACKAGE)" {
		t.Fatalf("lines = %q", lines)
	}
}

func TestGovulncheckOutputCap(t *testing.T) {
	s := cfg
	for i := 0; i < 60; i++ {
		s += findingMsg(fmt.Sprintf("GO-2025-%04d", i), "v1", fmt.Sprintf(`{"module":"m%d","version":"v1","package":"p","function":"F"}`, i))
	}
	lines, failed := run(t, govulncheck, s, nil)
	if !failed {
		t.Fatal("want failure")
	}
	fails := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "FAIL govulncheck ") {
			fails++
		}
	}
	if fails != 50 {
		t.Errorf("finding lines = %d, want 50", fails)
	}
	wantLine(t, lines, "... and 10 more")
	if last(lines) != "FAIL 60 blocking finding(s)" {
		t.Errorf("last line = %q", last(lines))
	}
}

func TestGovulncheckHugeField(t *testing.T) {
	huge := strings.Repeat("A", 1_000_000)
	s := cfg + findingMsg("GO-2025-0001", "v1", `{"module":"`+huge+`","version":"v1","package":"p","function":"F"}`) +
		findingMsg("GO-2025-0002", "v1", `{"module":"`+huge+`","version":"v1"}`)
	lines, failed := run(t, govulncheck, s, nil)
	if !failed {
		t.Fatal("want failure")
	}
	for _, l := range lines {
		if len(l) > 600 {
			t.Fatalf("line of %d bytes", len(l))
		}
	}
}

func TestGovulncheckErrors(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"whitespace":       "  \n\t ",
		"not-json":         "hello",
		"array":            "[]",
		"no-config":        findingMsg("GO-1", "v1", `{"module":"m","version":"v1"}`),
		"mid-object":       fixture(t, "govulncheck-high.json")[:300],
		"mid-stream":       strings.TrimRight(fixture(t, "govulncheck-high.json"), "\n ")[:len(strings.TrimRight(fixture(t, "govulncheck-high.json"), "\n "))-3],
		"null-config":      `{"config":null}`,
		"unknown-message":  cfg + `{"mystery":{}}`,
		"trailing-garbage": cfg + "}}}",
		"finding-no-osv":   cfg + `{"finding":{"fixed_version":"v1","trace":[{"module":"m","version":"v1"}]}}`,
		"finding-no-trace": cfg + `{"finding":{"osv":"GO-1","fixed_version":"v1"}}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Govulncheck(strings.NewReader(text), nil, testNow); err == nil {
				t.Fatal("want error (fail closed)")
			}
		})
	}
}

func TestGovulncheckBOMAndCRLF(t *testing.T) {
	text := "\xef\xbb\xbf" + strings.ReplaceAll(fixture(t, "govulncheck-clean.json"), "\n", "\r\n")
	lines, failed := run(t, govulncheck, text, nil)
	if failed || last(lines) != "OK govulncheck: 0 blocking, 0 warning(s)" {
		t.Fatalf("failed=%v lines=%q", failed, lines)
	}
}

func TestPnpmHighAndWaiver(t *testing.T) {
	high := fixture(t, "pnpm-audit-high.json")
	lines, failed := run(t, pnpm, high, nil)
	if !failed {
		t.Fatal("want failure")
	}
	wantLine(t, lines, "FAIL pnpm GHSA-35jh-r3h4-6jhm lodash high patched >=4.17.21")
	a := allowlist(t, "entries:\n  - id: GHSA-35jh-r3h4-6jhm\n    reason: r\n    approver: Sol\n    expires: 2026-12-31\n")
	lines, failed = run(t, pnpm, high, a)
	if !failed || last(lines) != "FAIL 1 blocking finding(s)" {
		t.Fatalf("failed=%v lines=%q", failed, lines)
	}
	a = allowlist(t, "entries:\n  - id: GHSA-35jh-r3h4-6jhm\n    reason: r\n    approver: Sol\n    expires: 2026-12-31\n  - id: GHSA-p6mc-m468-83gw\n    reason: r\n    approver: Sol\n    expires: 2026-12-31\n")
	lines, failed = run(t, pnpm, high, a)
	if failed || last(lines) != "OK pnpm audit: 0 blocking, 0 below threshold, 2 waived" {
		t.Fatalf("failed=%v lines=%q", failed, lines)
	}
}

func TestPnpmSeverities(t *testing.T) {
	high := fixture(t, "pnpm-audit-high.json")
	pass := map[string]string{"info": "info", "low": "low", "moderate": "moderate"}
	for sev := range pass {
		t.Run(sev, func(t *testing.T) {
			text := strings.ReplaceAll(high, `"severity": "high"`, `"severity": "`+sev+`"`)
			lines, failed := run(t, pnpm, text, nil)
			if failed || len(lines) != 1 || lines[0] != "OK pnpm audit: 0 blocking, 2 below threshold" {
				t.Fatalf("failed=%v lines=%q", failed, lines)
			}
		})
	}
	for _, sev := range []string{"catastrophic", "HIGH", "", "severe"} {
		t.Run("unknown-"+sev, func(t *testing.T) {
			text := strings.ReplaceAll(high, `"severity": "high"`, `"severity": "`+sev+`"`)
			lines, failed := run(t, pnpm, text, nil)
			if !failed {
				t.Fatal("unknown severity must fail closed")
			}
			wantContains(t, lines, "FAIL pnpm GHSA-35jh-r3h4-6jhm", "unknown severity")
		})
	}
}

func TestPnpmClean(t *testing.T) {
	lines, failed := run(t, pnpm, fixture(t, "pnpm-audit-clean.json"), nil)
	if failed || len(lines) != 1 || lines[0] != "OK pnpm audit: 0 blocking, 0 below threshold" {
		t.Fatalf("failed=%v lines=%q", failed, lines)
	}
}

func TestPnpmErrors(t *testing.T) {
	cases := map[string]string{
		"empty":       "",
		"no-lockfile": `{"error":{"code":"ERR_PNPM_AUDIT_NO_LOCKFILE","message":"x"}}`,
		"no-advisory": `{"metadata":{}}`,
		"null":        `{"advisories":null}`,
		"array":       `[]`,
		"truncated":   fixture(t, "pnpm-audit-high.json")[:200],
		"two-objects": fixture(t, "pnpm-audit-clean.json") + fixture(t, "pnpm-audit-clean.json"),
		"wrong-type":  `{"advisories":[]}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Pnpm(strings.NewReader(text), nil, testNow); err == nil {
				t.Fatal("want error (fail closed)")
			}
		})
	}
}

func TestPnpmBOMOutputCapAndHugeField(t *testing.T) {
	lines, failed := run(t, pnpm, "\xef\xbb\xbf"+fixture(t, "pnpm-audit-clean.json"), nil)
	if failed || len(lines) != 1 {
		t.Fatalf("BOM: failed=%v lines=%q", failed, lines)
	}
	huge := strings.Repeat("B", 1_000_000)
	var b strings.Builder
	b.WriteString(`{"advisories":{`)
	for i := 0; i < 60; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		mod := "m"
		if i == 0 {
			mod = huge
		}
		fmt.Fprintf(&b, `"%d":{"id":%d,"title":"t","module_name":"%s","vulnerable_versions":"<2","patched_versions":">=2","severity":"critical","github_advisory_id":"GHSA-%04d","url":"u","findings":[]}`, i, i, mod, i)
	}
	b.WriteString(`},"metadata":{}}`)
	lines, failed = run(t, pnpm, b.String(), nil)
	if !failed {
		t.Fatal("want failure")
	}
	wantLine(t, lines, "... and 10 more")
	for _, l := range lines {
		if len(l) > 600 {
			t.Fatalf("line of %d bytes", len(l))
		}
	}
	if last(lines) != "FAIL 60 blocking finding(s)" {
		t.Errorf("last line = %q", last(lines))
	}
}

// trivyDoc builds a Trivy-shaped document with one result and the given
// vulnerability objects.
func trivyDoc(vulns ...string) string {
	return `{"SchemaVersion":2,"ArtifactName":"app:test","Results":[{"Target":"app:test (alpine 3.19)","Vulnerabilities":[` +
		strings.Join(vulns, ",") + `]}]}`
}

func trivyVuln(id, sev string) string {
	return `{"VulnerabilityID":"` + id + `","PkgName":"libssl3","InstalledVersion":"3.1.0","FixedVersion":"3.1.1","Severity":"` + sev + `"}`
}

func TestImageSeverities(t *testing.T) {
	for _, sev := range []string{"HIGH", "CRITICAL"} {
		t.Run(sev, func(t *testing.T) {
			lines, failed := run(t, image, trivyDoc(trivyVuln("CVE-2024-1111", sev)), nil)
			if !failed {
				t.Fatal("want failure")
			}
			wantContains(t, lines, "FAIL image CVE-2024-1111 libssl3@3.1.0", sev, "fixed 3.1.1")
		})
	}
	for _, sev := range []string{"UNKNOWN", "LOW", "MEDIUM"} {
		t.Run(sev, func(t *testing.T) {
			lines, failed := run(t, image, trivyDoc(trivyVuln("CVE-2024-1111", sev)), nil)
			if failed || len(lines) != 1 || lines[0] != "OK image scan: 0 blocking" {
				t.Fatalf("failed=%v lines=%q", failed, lines)
			}
		})
	}
	for _, sev := range []string{"SEVERE", "high", ""} {
		t.Run("unknown-"+sev, func(t *testing.T) {
			lines, failed := run(t, image, trivyDoc(trivyVuln("CVE-2024-1111", sev)), nil)
			if !failed {
				t.Fatal("unknown severity must fail closed")
			}
			wantContains(t, lines, "FAIL image CVE-2024-1111", "unknown severity")
		})
	}
}

func TestImageShapes(t *testing.T) {
	noFix := `{"VulnerabilityID":"CVE-2024-2222","PkgName":"zlib","InstalledVersion":"1.0","Severity":"HIGH"}`
	lines, failed := run(t, image, trivyDoc(noFix), nil)
	if !failed {
		t.Fatal("want failure")
	}
	wantContains(t, lines, "CVE-2024-2222 zlib@1.0", "fixed none")
	for name, text := range map[string]string{
		"null-vulnerabilities":   `{"Results":[{"Target":"t","Vulnerabilities":null}]}`,
		"absent-vulnerabilities": `{"Results":[{"Target":"t","Class":"lang-pkgs"}]}`,
		"empty-results":          `{"Results":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			lines, failed := run(t, image, text, nil)
			if failed || len(lines) != 1 {
				t.Fatalf("failed=%v lines=%q", failed, lines)
			}
		})
	}
	a := allowlist(t, "entries:\n  - id: CVE-2024-2222\n    reason: r\n    approver: Sol\n    expires: 2026-12-31\n")
	lines, failed = run(t, image, trivyDoc(noFix), a)
	if failed || last(lines) != "OK image scan: 0 blocking, 1 waived" {
		t.Fatalf("waiver: failed=%v lines=%q", failed, lines)
	}
}

func TestImageErrors(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"no-results":   `{"SchemaVersion":2,"ArtifactName":"x"}`,
		"null-results": `{"Results":null}`,
		"truncated":    `{"Results":[{"Target":"t","Vulnerabilities":[{"VulnerabilityID":"CVE-1"`,
		"array":        `[]`,
		"bad-type":     `{"Results":{}}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Image(strings.NewReader(text), nil, testNow); err == nil {
				t.Fatal("want error (fail closed)")
			}
		})
	}
	lines, _ := run(t, image, "\xef\xbb\xbf"+fixture(t, "image-scan-clean.json"), nil)
	if len(lines) != 1 {
		t.Errorf("BOM not skipped: %q", lines)
	}
}

func TestImageHugeFieldAndOrder(t *testing.T) {
	huge := strings.Repeat("C", 1_000_000)
	v := `{"VulnerabilityID":"CVE-2024-9","PkgName":"` + huge + `","InstalledVersion":"1","Severity":"CRITICAL"}`
	lines, failed := run(t, image, trivyDoc(v), nil)
	if !failed {
		t.Fatal("want failure")
	}
	for _, l := range lines {
		if len(l) > 600 {
			t.Fatalf("line of %d bytes", len(l))
		}
	}
	a, _ := run(t, image, trivyDoc(trivyVuln("CVE-2024-2", "HIGH"), trivyVuln("CVE-2024-1", "HIGH")), nil)
	b, _ := run(t, image, trivyDoc(trivyVuln("CVE-2024-1", "HIGH"), trivyVuln("CVE-2024-2", "HIGH")), nil)
	if strings.Join(a, "\n") != strings.Join(b, "\n") || len(a) == 0 || !strings.Contains(a[0], "CVE-2024-1") {
		t.Fatalf("not deterministic:\n%q\n%q", a, b)
	}
}

func TestClip(t *testing.T) {
	if got := Clip("short"); got != "short" {
		t.Errorf("Clip(short) = %q", got)
	}
	got := Clip(strings.Repeat("x", 1_000_000))
	if !strings.HasPrefix(got, strings.Repeat("x", 200)) || !strings.Contains(got, "1000000") || len(got) > 260 {
		t.Errorf("Clip(huge) = %q", got)
	}
	if got := Clip("line1\nline2\x1b[31m"); strings.ContainsAny(got, "\n\x1b") {
		t.Errorf("control characters survived: %q", got)
	}
	multi := strings.Repeat("é", 150)
	if got := Clip(multi); !strings.HasPrefix(multi, strings.SplitN(got, "…", 2)[0]) {
		t.Errorf("Clip cut inside a rune: %q", got)
	}
}

// TestNoPanicOnOddInput feeds every parser odd bytes. All of them are invalid
// for all three parsers, so each must return an error and none may panic.
func TestNoPanicOnOddInput(t *testing.T) {
	odd := map[string]string{
		"null": "null", "true": "true", "number": "12", "string": `"x"`, "array": "[]", "object": "{}",
		"open-brace": "{", "open-bracket": "[", "key-only": `{"config":`, "bom-only": "\xef\xbb\xbf",
		"nul": "\x00", "high-bytes": "\xff\xfe\xfd", "deep": strings.Repeat("[", 100000),
		"deep-obj": strings.Repeat(`{"a":`, 5000), "lone-quote": `"`, "slash": "/", "bad-escape": `{"a":"\q"}`,
		"surrogate": `{"a":"\ud800"}`, "comma": ",", "nested-null": `{"finding":null}`,
		"progress-only": `{"progress":{"message":"x"}}`, "advisories-str": `{"advisories":"x"}`,
		"results-str": `{"Results":"x"}`, "huge-number": `{"a":` + strings.Repeat("9", 100000) + `}`,
	}
	for name, text := range odd {
		for pname, fn := range map[string]scanFn{"govulncheck": govulncheck, "pnpm": pnpm, "image": image} {
			t.Run(pname+"/"+name, func(t *testing.T) {
				if _, err := fn(strings.NewReader(text), nil, testNow); err == nil {
					t.Fatal("want error")
				}
			})
		}
		t.Run("allowlist/"+name, func(t *testing.T) {
			if _, err := ParseAllowlist([]byte(text)); err == nil && name != "bom-only" {
				t.Fatal("want error")
			}
		})
	}
}

const cfgOnly = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.9.0","scan_level":"symbol","scan_mode":"source"}}` + "\n"

// cfg is the head of a complete stream: the config message and the two
// progress messages that real govulncheck -json emits before any finding.
const cfg = cfgOnly +
	`{"progress":{"message":"first"}}` + "\n" +
	`{"progress":{"message":"second"}}` + "\n"

func osvMsg(id string) string {
	return `{"osv":{"id":"` + id + `","aliases":["CVE-2025-0001"]}}` + "\n"
}

func findingMsg(id, fixed, frame string) string {
	return `{"finding":{"osv":"` + id + `","fixed_version":"` + fixed + `","trace":[` + frame + `]}}` + "\n"
}
