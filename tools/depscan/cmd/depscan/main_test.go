package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var empty = filepath.Join("..", "..", "testdata", "allowlist-empty.yaml")

func td(name string) string { return filepath.Join("..", "..", "testdata", name) }

func exec(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runWith(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{
		nil, {"bogus"}, {"govulncheck"}, {"pnpm"}, {"image"}, {"govulncheck", "a", "b"},
		{"govulncheck", "-nosuchflag", "x"}, {"pnpm", "-now", "yesterday", "-allowlist", empty, td("pnpm-audit-clean.json")},
		{"image", "-now"},
	} {
		code, out, errb := exec(t, "", args...)
		if code != 2 || out != "" || !strings.HasPrefix(errb, "usage: depscan ") {
			t.Errorf("%q: code=%d out=%q err=%q", args, code, out, errb)
		}
	}
}

func TestExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"govulncheck-clean", []string{"govulncheck", "-allowlist", empty, td("govulncheck-clean.json")}, 0, "OK govulncheck: 0 blocking, 0 warning(s)\n"},
		{"govulncheck-high", []string{"govulncheck", "-allowlist", empty, td("govulncheck-high.json")}, 1, "FAIL govulncheck GO-2026-6617 "},
		{"flags-after-file", []string{"govulncheck", td("govulncheck-high.json"), "-allowlist", empty}, 1, "FAIL govulncheck GO-2026-6617 "},
		{"pnpm-clean", []string{"pnpm", "-allowlist", empty, td("pnpm-audit-clean.json")}, 0, "OK pnpm audit: 0 blocking, 0 below threshold\n"},
		{"pnpm-critical", []string{"pnpm", "-allowlist", empty, td("pnpm-audit-critical.json")}, 1, "FAIL pnpm GHSA-35jh-r3h4-6jhm lodash critical"},
		{"image-clean", []string{"image", "-allowlist", empty, td("image-scan-clean.json")}, 0, "OK image scan: 0 blocking\n"},
		{"waived", []string{"govulncheck", "-allowlist", td("waiver-symbol.yaml"), "-now", "2026-06-01T00:00:00Z", td("govulncheck-high.json")}, 0, "OK govulncheck: 0 blocking, 1 warning(s), 1 waived\n"},
		{"waiver-expired-by-now", []string{"govulncheck", "-allowlist", td("waiver-symbol.yaml"), "-now", "2027-01-01T00:00:00Z", td("govulncheck-high.json")}, 1, "FAIL govulncheck GO-2026-6617 "},
		{"expired-no-finding", []string{"govulncheck", "-allowlist", td("expired-exception.yaml"), "-now", "2026-06-01T00:00:00Z", td("expired-exception.json")}, 1, "FAIL expired exception GO-2024-0001 (expired 2026-01-31)\nFAIL 1 blocking finding(s)\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errb := exec(t, "", c.args...)
			if code != c.code || errb != "" || !strings.Contains(out, c.out) {
				t.Fatalf("code=%d err=%q out=%q", code, errb, out)
			}
		})
	}
}

func TestStdin(t *testing.T) {
	b, err := os.ReadFile(td("pnpm-audit-critical.json"))
	if err != nil {
		t.Fatal(err)
	}
	code, out, errb := exec(t, string(b), "pnpm", "-allowlist", empty, "-")
	if code != 1 || errb != "" || !strings.HasSuffix(out, "FAIL 2 blocking finding(s)\n") {
		t.Fatalf("code=%d err=%q out=%q", code, errb, out)
	}
}

func TestErrorsFailClosed(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"empty-stdin", "", []string{"govulncheck", "-allowlist", empty, "-"}, "depscan: "},
		{"garbage", "not json", []string{"pnpm", "-allowlist", empty, "-"}, "depscan: "},
		{"missing-file", "", []string{"image", "-allowlist", empty, td("does-not-exist.json")}, "depscan: "},
		{"missing-allowlist", "", []string{"image", "-allowlist", td("does-not-exist.yaml"), td("image-scan-clean.json")}, "depscan: "},
		{"no-results", `{"x":1}`, []string{"image", "-allowlist", empty, "-"}, "depscan: "},
		{"no-lockfile-json", `{"error":{"code":"ERR_PNPM_AUDIT_NO_LOCKFILE"}}`, []string{"pnpm", "-allowlist", empty, "-"}, "depscan: "},
		{"truncated-stream", `{"config":{"scanner_name":"govulncheck"}}` + "\n" + `{"finding":{"osv":"GO-1"`, []string{"govulncheck", "-allowlist", empty, "-"}, "depscan: "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errb := exec(t, c.stdin, c.args...)
			if code != 1 || out != "" || !strings.HasPrefix(errb, c.want) || strings.Count(errb, "\n") != 1 {
				t.Fatalf("code=%d out=%q err=%q", code, out, errb)
			}
		})
	}
}

func TestBadAllowlistNamesLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.yaml")
	if err := os.WriteFile(p, []byte("entries:\n  - id: GO-1\n    bogus: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := exec(t, "", "image", "-allowlist", p, td("image-scan-clean.json"))
	if code != 1 || out != "" || !strings.HasPrefix(errb, "depscan: ") || !strings.Contains(errb, "line 3") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
}

func TestDefaultAllowlistPath(t *testing.T) {
	if defaultAllowlist != "tools/depscan/allowlist.yaml" {
		t.Errorf("defaultAllowlist = %q", defaultAllowlist)
	}
}

func TestRunUsesStdoutAndStderr(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"image", "-allowlist", empty, td("image-scan-clean.json")}, &out, &errb); code != 0 || out.Len() == 0 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errb.String())
	}
}

func TestCLIDuplicateKeyAndIncompleteStream(t *testing.T) {
	code, out, errb := exec(t, `{"Results":[],"SECRETKEY":1,"SECRETKEY":2}`, "image", "-allowlist", empty, "-")
	if code != 1 || out != "" || !strings.HasPrefix(errb, "depscan: duplicate key in image scan output at byte offset ") ||
		strings.Contains(errb, "SECRETKEY") {
		t.Errorf("duplicate key: code=%d out=%q err=%q", code, out, errb)
	}
	cut := `{"config":{"scanner_name":"govulncheck"}}` + "\n"
	code, out, errb = exec(t, cut, "govulncheck", "-allowlist", empty, "-")
	want := "depscan: govulncheck stream incomplete (the scan did not reach the check phase)\n"
	if code != 1 || out != "" || errb != want {
		t.Errorf("incomplete: code=%d out=%q err=%q", code, out, errb)
	}
}

// Nothing from an input or a path is echoed beyond 200 bytes: the message is
// clipped, with an ellipsis and the original length.
func TestErrorsAreClippedTo200Bytes(t *testing.T) {
	huge := strings.Repeat("A", 1_000_000)
	check := func(name, errb string) {
		t.Helper()
		if !strings.HasPrefix(errb, "depscan: ") || strings.Count(errb, "A") > 200 || len(errb) > 300 {
			t.Errorf("%s: %d bytes with %d A's", name, len(errb), strings.Count(errb, "A"))
		}
		if !strings.Contains(errb, "bytes)") {
			t.Errorf("%s: no clip marker in %q", name, errb)
		}
	}
	_, _, errb := exec(t, "", "image", "-allowlist", empty, huge)
	check("input path", errb)
	_, _, errb = exec(t, "", "image", "-allowlist", huge, td("image-scan-clean.json"))
	check("allowlist path", errb)
	var buf bytes.Buffer
	if code := fail(&buf, errors.New("stream error: bad token "+huge)); code != 1 {
		t.Errorf("fail code = %d", code)
	}
	check("stream error", buf.String())
}
