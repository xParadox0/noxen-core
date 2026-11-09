package depscan

import (
	"strings"
	"testing"
)

// A waived SYMBOL advisory that also has module-level findings must not
// leave a warning behind: the advisory is waived, not downgraded.
func TestWaivedSymbolAdvisoryWithModuleFindingHasNoWarning(t *testing.T) {
	s := cfg +
		findingMsg("GO-2025-0001", "v1", `{"module":"m","version":"v1","package":"p","function":"F"}`) +
		findingMsg("GO-2025-0001", "v1", `{"module":"m","version":"v1"}`) +
		findingMsg("GO-2025-0001", "v1", `{"module":"m","version":"v1","package":"p"}`)
	a := allowlist(t, "entries:\n  - id: GO-2025-0001\n    reason: r\n    approver: Sol\n    expires: 2026-12-31\n")
	lines, failed := run(t, govulncheck, s, a)
	if failed || len(lines) != 1 || lines[0] != "OK govulncheck: 0 blocking, 0 warning(s), 1 waived" {
		t.Fatalf("failed=%v lines=%q", failed, lines)
	}
}

// The input cap is a variable so that this test needs a few KiB, not 256 MiB.
func TestInputCap(t *testing.T) {
	old := maxInput
	t.Cleanup(func() { maxInput = old })
	maxInput = 4096
	over := strings.Repeat(" ", 5000)
	for name, fn := range map[string]scanFn{"govulncheck": govulncheck, "pnpm": pnpm, "image": image} {
		t.Run(name+"/over", func(t *testing.T) {
			_, err := fn(strings.NewReader(over), nil, testNow)
			if err == nil || !strings.Contains(err.Error(), "input larger than 4096 bytes") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("pnpm/under", func(t *testing.T) {
		text := `{"advisories":{}}` + strings.Repeat(" ", 4000)
		if _, err := Pnpm(strings.NewReader(text), nil, testNow); err != nil {
			t.Fatalf("under the cap: %v", err)
		}
	})
	t.Run("pnpm/restored", func(t *testing.T) {
		maxInput = old
		if _, err := Pnpm(strings.NewReader(`{"advisories":{}}`+over), nil, testNow); err != nil {
			t.Fatalf("after restore: %v", err)
		}
	})
}
