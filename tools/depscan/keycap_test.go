package depscan

import (
	"fmt"
	"strings"
	"testing"
)

// setMaxKeys lowers the key cap for one test.
func setMaxKeys(t *testing.T, n int) {
	t.Helper()
	old := maxKeys
	t.Cleanup(func() { maxKeys = old })
	maxKeys = n
}

func TestKeyCapDefault(t *testing.T) {
	if maxKeys != 2_000_000 {
		t.Fatalf("maxKeys = %d, want 2000000", maxKeys)
	}
}

// keyDoc builds an array of n one-key objects, so n keys in total.
func keyDoc(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"k%d":1}`, i)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestKeyCapCheckKeys(t *testing.T) {
	setMaxKeys(t, 5)
	cases := []struct {
		name string
		doc  string
		fail bool
	}{
		{"exactly-limit", `{"a":1,"b":2,"c":3,"d":4,"e":5}`, false},
		{"one-more", `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6}`, true},
		{"across-objects-at-limit", keyDoc(5), false},
		{"across-objects-over", keyDoc(6), true},
		{"nested-at-limit", `{"a":{"b":1,"c":{"d":1}},"e":[1]}`, false},
		{"nested-over", `{"a":{"b":1,"c":{"d":1}},"e":[{"f":1}]}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkKeys([]byte(c.doc), 0, "test input")
			if !c.fail {
				if err != nil {
					t.Fatalf("error: %v", err)
				}
				return
			}
			if err == nil || err.Error() != "more than 5 object keys in test input" {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestKeyCapScanners(t *testing.T) {
	secret := "SECRETKEYNAME"
	// Each case holds exactly limit keys in its largest document, or limit+1
	// when over is set; the secret name is one of the keys.
	cases := []struct {
		name  string
		fn    scanFn
		limit int
		doc   func(over bool) string
	}{
		{"pnpm", pnpm, 5, func(over bool) string {
			return `{"advisories":{},"x":` + keyDocWith(3+b2i(over), secret) + `}`
		}},
		{"image", image, 5, func(over bool) string {
			return `{"Results":[],"x":` + keyDocWith(3+b2i(over), secret) + `}`
		}},
		// the cap applies to each message; the config message has 6 keys.
		{"govulncheck", govulncheck, 6, func(over bool) string {
			extra := ""
			if over {
				extra = `,"` + secret + `":1`
			}
			return strings.Replace(cfg, `"scan_mode":"source"`, `"scan_mode":"source"`+extra, 1)
		}},
	}
	for _, c := range cases {
		t.Run(c.name+"/at-limit", func(t *testing.T) {
			setMaxKeys(t, c.limit)
			_, err := c.fn(strings.NewReader(c.doc(false)), nil, testNow)
			if err != nil && strings.Contains(err.Error(), "object keys") {
				t.Fatalf("at the limit: %v", err)
			}
		})
		t.Run(c.name+"/over", func(t *testing.T) {
			setMaxKeys(t, c.limit)
			_, err := c.fn(strings.NewReader(c.doc(true)), nil, testNow)
			want := fmt.Sprintf("more than %d object keys in ", c.limit)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error echoes a key: %v", err)
			}
		})
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// keyDocWith builds an array of n one-key objects whose last key is name.
func keyDocWith(n int, name string) string {
	if n < 1 {
		n = 1
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"k%d":1}`, i)
	}
	parts[n-1] = `{"` + name + `":1}`
	return "[" + strings.Join(parts, ",") + "]"
}
