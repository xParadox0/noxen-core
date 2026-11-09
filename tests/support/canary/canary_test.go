package canary

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"chronyxlabs.com/noxen-studio/internal/redact"
)

var shape = regexp.MustCompile(`^NXCANARY-([a-z0-9]+)-[0-9a-f]{32}$`)

func TestNewIsUniqueAndSynthetic(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		v := New("secret")
		m := shape.FindStringSubmatch(v)
		if m == nil || m[1] != "secret" {
			t.Fatalf("New returned %d bytes that do not have the NXCANARY-secret-<32 hex> shape", len(v))
		}
		if err := redact.ValidCanary(v); err != nil {
			t.Fatalf("New value fails ValidCanary: %v", err)
		}
		if seen[v] {
			t.Fatal("New returned a duplicate value")
		}
		seen[v] = true
	}
	if v := New("plaintext"); !strings.HasPrefix(v, "NXCANARY-plaintext-") {
		t.Fatal("New does not carry the kind in its prefix")
	}
}

func TestNewRejectsBadKind(t *testing.T) {
	for _, kind := range []string{"", "Upper", "with space", "dash-ed", strings.Repeat("k", 33)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("New(%q) did not panic", kind)
				}
			}()
			New(kind)
		}()
	}
}

func TestRegister(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "registry.txt")
	a, b := New("secret"), New("plaintext")
	if err := Register(path, a); err == nil {
		t.Fatal("Register into a missing directory succeeded")
	}
	path = filepath.Join(t.TempDir(), "registry.txt")
	if err := Register(path, a); err != nil {
		t.Fatalf("Register: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("registry created with mode %o, want 600", perm)
	}
	if err := Register(path, b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != a+"\n"+b+"\n" {
		t.Fatalf("registry holds %d bytes, want the two values one per line", len(data))
	}
	vals, err := redact.ParseCanaries(data)
	if err != nil || len(vals) != 2 || vals[0] != a || vals[1] != b {
		t.Fatalf("registry does not parse back to the two values (%d, %v)", len(vals), err)
	}
	if got := string(redact.Bytes([]byte("x "+b+" y"), redact.WithCanaries(vals))); got != "x [REDACTED:canary] y" {
		t.Fatalf("a registered value is not redacted (output %d bytes)", len(got))
	}
}

func TestRegisterAddsMissingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.txt")
	if err := os.WriteFile(path, []byte("# header without newline"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := New("secret")
	if err := Register(path, v); err != nil {
		t.Fatalf("Register: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "# header without newline\n"+v+"\n" {
		t.Fatalf("value was not appended on its own line (%d bytes)", len(data))
	}
}

func TestRegisterRejectsInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.txt")
	for _, v := range []string{"", "short", "has a space in it", "#comment-like-value", strings.Repeat("x", 257), "line\nbreak-value"} {
		err := Register(path, v)
		if err == nil {
			t.Fatalf("Register accepted an invalid value of %d bytes", len(v))
		}
		if v != "" && strings.Contains(err.Error(), v) {
			t.Fatal("Register error echoes the value")
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("Register created the registry for invalid values: %v", err)
	}
}
