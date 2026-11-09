package depscan

import (
	"fmt"
	"strings"
	"testing"
)

// Two progress messages do not replace the config message.
func TestGovulncheckProgressWithoutConfig(t *testing.T) {
	text := progMsg + progMsg + sbomMsg + osvMsg("GO-2025-0001")
	if _, err := Govulncheck(strings.NewReader(text), nil, testNow); err == nil {
		t.Fatal("want error: no config message")
	}
}

// The reported offset is where the repeated key ends, counted from the first
// byte of the input, a byte order mark included, and from the stream start for
// a govulncheck message.
func TestDuplicateKeyOffsets(t *testing.T) {
	const doc = `{"advisories":{},"a":1,"a":2}`
	cases := []struct {
		name string
		fn   scanFn
		text string
		off  int
	}{
		{"pnpm", pnpm, doc, 26},
		{"pnpm-bom", pnpm, "\xef\xbb\xbf" + doc, 29},
		{"govulncheck-second-message", govulncheck, cfgOnly + `{"progress":{"m":1,"m":2}}`, len(cfgOnly) + 22},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.fn(strings.NewReader(c.text), nil, testNow)
			if err == nil || !strings.HasSuffix(err.Error(), fmt.Sprintf("at byte offset %d", c.off)) {
				t.Fatalf("err = %v, want offset %d", err, c.off)
			}
		})
	}
}
