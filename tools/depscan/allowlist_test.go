package depscan

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const goodItem = "  - id: GO-2024-2687\n    reason: short text\n    approver: Sol\n    expires: 2026-12-31\n"

func TestAllowlistValid(t *testing.T) {
	cases := map[string]string{
		"full":         "# comment\nentries:\n" + goodItem,
		"any-order":    "entries:\n  - expires: 2026-12-31\n    approver: Sol\n    id: GO-2024-2687\n    reason: short text\n",
		"quoted":       "entries:\n  - id: \"GO-2024-2687\"\n    reason: \"text: with colon\"\n    approver: \"Sol\"\n    expires: \"2026-12-31\"\n",
		"comments":     "# a\n\nentries:\n  # b\n" + goodItem + "\n# c\n",
		"crlf":         strings.ReplaceAll("entries:\n"+goodItem, "\n", "\r\n"),
		"bom":          "\xef\xbb\xbfentries:\n" + goodItem,
		"trailing-sp":  "entries:  \n" + strings.ReplaceAll(goodItem, "text\n", "text  \n"),
		"two":          "entries:\n" + goodItem + strings.ReplaceAll(goodItem, "GO-2024-2687", "CVE-2024-1"),
		"no-final-nl":  strings.TrimSuffix("entries:\n"+goodItem, "\n"),
		"cve-and-ghsa": "entries:\n" + strings.ReplaceAll(goodItem, "GO-2024-2687", "GHSA-4v7x-pqxf-cx7m"),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			a, err := ParseAllowlist([]byte(text))
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			want := 1
			if name == "two" {
				want = 2
			}
			if len(a) != want {
				t.Fatalf("entries = %d, want %d", len(a), want)
			}
			if name == "any-order" || name == "full" {
				e := a[0]
				if e.ID != "GO-2024-2687" || e.Reason != "short text" || e.Approver != "Sol" {
					t.Errorf("entry = %+v", e)
				}
				if !e.Expires.Equal(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) {
					t.Errorf("expires = %v", e.Expires)
				}
			}
		})
	}
}

func TestAllowlistEmpty(t *testing.T) {
	for name, text := range map[string]string{
		"empty": "", "newline": "\n", "comments-only": "# x\n# y\n", "flow-empty": "entries: []\n",
		"flow-empty-comment": "# c\nentries: []", "bom-only": "\xef\xbb\xbf",
	} {
		t.Run(name, func(t *testing.T) {
			a, err := ParseAllowlist([]byte(text))
			if err != nil || len(a) != 0 {
				t.Fatalf("entries=%v err=%v", a, err)
			}
		})
	}
}

func TestAllowlistRejections(t *testing.T) {
	item := func(mod func(lines []string) []string) string {
		l := mod([]string{"entries:", "  - id: GO-2024-2687", "    reason: short text", "    approver: Sol", "    expires: 2026-12-31"})
		return strings.Join(l, "\n") + "\n"
	}
	set := func(i int, v string) func([]string) []string {
		return func(l []string) []string { l[i] = v; return l }
	}
	cases := []struct {
		name, text string
		line       int
	}{
		{"unknown-key", item(func(l []string) []string { return append(l, "    extra: x") }), 6},
		{"missing-approver", item(func(l []string) []string { return append(l[:3], l[4]) }), 2},
		{"missing-id", item(func(l []string) []string { return []string{l[0], "  - reason: r", l[3], l[4]} }), 2},
		{"duplicate-key", item(func(l []string) []string { return append(l, "    reason: again") }), 6},
		{"duplicate-id", item(func(l []string) []string { return append(l, l[1:]...) }), 6},
		{"tab-indent", item(set(2, "\treason: short text")), 3},
		{"tab-inside", item(set(2, "    reason: short\ttext")), 3},
		{"tab-list", item(set(1, "\t- id: GO-2024-2687")), 2},
		{"anchor", item(set(2, "    reason: &a text")), 3},
		{"alias", item(set(2, "    reason: *a")), 3},
		{"tag", item(set(2, "    reason: !!str text")), 3},
		{"flow-seq", "entries: [a]\n", 1},
		{"flow-item", "entries:\n  - {id: A, reason: r, approver: Sol, expires: 2026-12-31}\n", 2},
		{"flow-value", item(set(2, "    reason: [a, b]")), 3},
		{"block-scalar", item(set(2, "    reason: |")), 3},
		{"folded-scalar", item(set(2, "    reason: >")), 3},
		{"multi-line", item(func(l []string) []string { return append(l[:3], "    reason: first", "      second", l[3], l[4]) }), 4},
		{"multi-line-quoted", item(set(2, "    reason: \"first")), 3},
		{"single-quote", item(set(2, "    reason: 'text'")), 3},
		{"text-after-quote", item(set(2, "    reason: \"text\" more")), 3},
		{"escape-in-quote", item(set(2, "    reason: \"a\\nb\"")), 3},
		{"inline-comment", item(set(2, "    reason: text # why")), 3},
		{"colon-in-plain", item(set(2, "    reason: a: b")), 3},
		{"empty-value", item(set(2, "    reason:")), 3},
		{"no-space-after-colon", item(set(2, "    reason:text")), 3},
		{"bad-date-day", item(set(4, "    expires: 2026-02-30")), 5},
		{"bad-date-short", item(set(4, "    expires: 2026-1-5")), 5},
		{"bad-date-word", item(set(4, "    expires: tomorrow")), 5},
		{"bad-date-time", item(set(4, "    expires: 2026-12-31T00:00:00Z")), 5},
		{"bad-id-chars", item(set(1, "  - id: GO 2024")), 2},
		{"wrong-indent-item", item(set(1, " - id: GO-2024-2687")), 2},
		{"wrong-indent-key", item(set(2, "   reason: short text")), 3},
		{"deep-indent-key", item(set(2, "      reason: short text")), 3},
		{"item-without-dash", item(set(1, "    id: GO-2024-2687")), 2},
		{"top-level-unknown", "foo: bar\n", 1},
		{"after-empty-flow", "entries: []\nextra: 1\n", 2},
		{"entries-no-items", "entries:\n", 1},
		{"second-entries", "entries:\n" + goodItem + "entries:\n", 6},
		{"cr-inside", item(set(2, "    reason: a\rb")), 3},
		{"control-char", item(set(2, "    reason: a\x01b")), 3},
		{"invalid-utf8", item(set(2, "    reason: a\xffb")), 3},
		{"long-line", item(set(2, "    reason: "+strings.Repeat("x", 5000))), 3},
		{"document-marker", "---\nentries: []\n", 1},
		{"list-at-top", "- id: A\n", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseAllowlist([]byte(c.text))
			if err == nil {
				t.Fatal("want error")
			}
			if want := fmt.Sprintf("line %d", c.line); !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %q", err, want)
			}
		})
	}
}

func TestAllowlistErrorsDoNotEchoContent(t *testing.T) {
	text := "entries:\n  - id: GO-2024-2687\n    reason: &SECRETVALUE\n    approver: Sol\n    expires: 2026-12-31\n"
	_, err := ParseAllowlist([]byte(text))
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "SECRETVALUE") {
		t.Errorf("error echoes input: %v", err)
	}
}

func TestRealAllowlistIsValidAndEmpty(t *testing.T) {
	b, err := readFile("allowlist.yaml")
	if err != nil {
		t.Fatalf("read allowlist.yaml: %v", err)
	}
	a, err := ParseAllowlist(b)
	if err != nil || len(a) != 0 {
		t.Fatalf("entries=%v err=%v", a, err)
	}
	if !strings.Contains(string(b), "Sol") || !strings.Contains(string(b), "expires") {
		t.Error("allowlist.yaml must document the Sol approver and the expiry")
	}
}
