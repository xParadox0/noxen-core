package redact

import (
	"reflect"
	"strings"
	"testing"
)

func TestValidCanary(t *testing.T) {
	tests := []struct {
		name string
		v    string
		ok   bool
	}{
		{"12 bytes", rep("a", 12), true},
		{"256 bytes", rep("b", 256), true},
		{"all printable", "!\"$%&'()*+,-./0123456789:;<=>?@AZ[\\]^_`az{|}~", true},
		{"hash inside", "abc#def12345", true},
		{"11 bytes", rep("a", 11), false},
		{"257 bytes", rep("a", 257), false},
		{"empty", "", false},
		{"space", "abcdef 123456", false},
		{"tab", "abcdef\t123456", false},
		{"newline", "abcdef\n123456", false},
		{"del", "abcdef\x7f123456", false},
		{"nul", "abcdef\x00123456", false},
		{"non-ascii", "abcdefé123456", false},
		{"leading hash reads as a comment", "#abcdef123456", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidCanary(tt.v); (err == nil) != tt.ok {
				t.Fatalf("ValidCanary error = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestParseCanaries(t *testing.T) {
	a, b := "zcanary-parse-aaaa", "zcanary-parse-bbbb"
	in := "# registry\n\n   \n" + a + "\r\n# comment\n  # indented comment\n" + b + "\n" + a + "\n" + b
	got, err := ParseCanaries([]byte(in))
	if err != nil {
		t.Fatalf("ParseCanaries: %v", err)
	}
	if want := []string{a, b}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseCanaries returned %d values, want 2 in file order without duplicates", len(got))
	}
	got, err = ParseCanaries(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty registry: %d values, %v", len(got), err)
	}
	got, err = ParseCanaries([]byte("# only comments\n# here\n"))
	if err != nil || len(got) != 0 {
		t.Fatalf("comment-only registry: %d values, %v", len(got), err)
	}
}

func TestParseCanariesErrorsNameTheLineOnly(t *testing.T) {
	good := "zcanary-good-value"
	tests := []struct {
		name string
		bad  string
		line string
	}{
		{"short", "short-value", "line 3"},
		{"space", "zcanary with space", "line 3"},
		{"long", rep("x", 257), "line 3"},
		{"leading space", " zcanary-leading", "line 3"},
		{"trailing space", "zcanary-trailing ", "line 3"},
		{"non-ascii", "zcanary-été-xyz", "line 3"},
		{"very long line", rep("y", 100000), "line 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCanaries([]byte("# c\n" + good + "\n" + tt.bad + "\n" + good + "\n"))
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			msg := err.Error()
			if !strings.Contains(msg, tt.line) {
				t.Fatalf("error does not name %s", tt.line)
			}
			if strings.Contains(msg, strings.TrimSpace(tt.bad)) || strings.Contains(msg, good) || len(msg) > 120 {
				t.Fatalf("error echoes registry content (%d bytes)", len(msg))
			}
		})
	}
}
