package redact

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Secret-shaped test values are assembled at run time from fragments, so no
// line of this file holds a complete one and the scanners stay green on it.
// Failure messages print kinds, offsets and lengths, never inputs or outputs.

func rep(s string, n int) string { return strings.Repeat(s, n) }

// cycle returns n bytes taken in turn from chars.
func cycle(chars string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[i%len(chars)]
	}
	return string(b)
}

const (
	alnumChars  = "aZ0bY1cX2dW3eV4fU5gT6hS7iR8jQ9kP"
	upperDigits = "A0B1C2D3E4F5G6H7J8K9"
	b64Chars    = "aZ0_bY1-cX2"
	bearerChars = "aZ0._~+/=-bY1"
	slackChars  = "aZ0-bY1"
)

var (
	preBearer = "Bear" + "er "
	preCF     = "CF_Auth" + "orization="
	pemBegin  = "-----BEG" + "IN "
	pemEnd    = "-----EN" + "D "
	pemTail   = "PRIVATE" + " KEY-----"
)

func bearer(n int) string           { return preBearer + cycle(bearerChars, n) }
func github(p string, n int) string { return "gh" + p + "_" + cycle(alnumChars, n) }
func githubPAT(n int) string        { return "github" + "_pat_" + cycle(alnumChars+"_", n) }
func aws(p string, n int) string    { return p + cycle(upperDigits, n) }
func slack(l string, n int) string  { return "xox" + l + "-" + cycle(slackChars, n) }
func sk(n int) string               { return "sk" + "-" + cycle(b64Chars, n) }
func google(n int) string           { return "AI" + "za" + cycle(b64Chars, n) }
func cfauth(v string) string        { return preCF + v }
func jwt(a, b, c int) string {
	return "ey" + "J" + cycle(b64Chars, a) + "." + cycle(b64Chars, b) + "." + cycle(b64Chars, c)
}
func pemBegins(label string) string { return pemBegin + label + pemTail }
func pemEnds(label string) string   { return pemEnd + label + pemTail }
func pemBlock(label string) string {
	return pemBegins(label) + "\nMIIEbody" + rep("Q", 40) + "\n" + rep("w", 64) + "\n" + pemEnds(label)
}

func red(kind string) string { return "[REDACTED:" + kind + "]" }

// ---- reference redactor --------------------------------------------------
//
// ref works on the whole buffer: at each position it tries every pattern as
// an anchored regular expression and every canary as a literal, takes the
// longest (a pattern wins a tie with a canary), and either replaces the match
// or copies one byte. It is slow and deliberately independent of the engine.

const refCap = 4096 // confirmation must fit in this many bytes (non-PEM)

type refPat struct {
	kind   string
	lits   []string // the regexp is only tried where one of these starts
	re     *regexp.Regexp
	accept func(b []byte, loc []int) int // match length, 0 for none
}

func whole(_ []byte, loc []int) int { return loc[1] }

var refPats = []refPat{
	{KindBearer, []string{preBearer}, regexp.MustCompile(`^` + preBearer + `[A-Za-z0-9._~+/=-]{16,}`), whole},
	{KindGitHub, []string{"gh", "github_pat_"}, regexp.MustCompile(`^(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`), whole},
	{KindAWS, []string{"AKIA", "ASIA"}, regexp.MustCompile(`^(?:AKIA|ASIA)[0-9A-Z]{16}`), func(b []byte, loc []int) int {
		if len(b) > 20 && (b[20] >= '0' && b[20] <= '9' || b[20] >= 'A' && b[20] <= 'Z') {
			return 0
		}
		return 20
	}},
	{KindSlack, []string{"xox"}, regexp.MustCompile(`^xox[abprs]-[A-Za-z0-9-]{10,}`), whole},
	{KindSK, []string{"sk-"}, regexp.MustCompile(`^sk-[A-Za-z0-9_-]{20,}`), whole},
	{KindGoogle, []string{"AIza"}, regexp.MustCompile(`^AIza[A-Za-z0-9_-]{35,}`), whole},
	{KindJWT, []string{"eyJ"}, regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{8,})`), func(_ []byte, loc []int) int {
		if loc[2]+8 > refCap {
			return 0
		}
		return loc[1]
	}},
	{KindCFAuth, []string{preCF}, regexp.MustCompile(`^` + preCF + `[^ \t\n\v\f\r;"']+`), whole},
}

var refPEM = regexp.MustCompile(`^` + pemBegin + `((?:[A-Z0-9]+ )*)` + pemTail)

func refMatch(b []byte, canaries []string) (string, int) {
	kind, n := "", 0
	for _, p := range refPats {
		hit := false
		for _, l := range p.lits {
			hit = hit || bytes.HasPrefix(b, []byte(l))
		}
		if !hit {
			continue
		}
		if loc := p.re.FindSubmatchIndex(b); loc != nil {
			if m := p.accept(b, loc); m > n {
				kind, n = p.kind, m
			}
		}
	}
	if bytes.HasPrefix(b, []byte(pemBegin)) {
		if loc := refPEM.FindSubmatchIndex(b); loc != nil && loc[3]-loc[2] <= 64 {
			end := []byte(pemEnds(string(b[loc[2]:loc[3]])))
			m := len(b)
			if k := bytes.Index(b[loc[1]:], end); k >= 0 {
				m = loc[1] + k + len(end)
			}
			if m > n {
				kind, n = KindPEM, m
			}
		}
	}
	for _, c := range canaries {
		if bytes.HasPrefix(b, []byte(c)) && len(c) > n {
			kind, n = KindCanary, len(c)
		}
	}
	return kind, n
}

func ref(b []byte, canaries []string) ([]byte, []Finding) {
	out := []byte{}
	var fs []Finding
	for i := 0; i < len(b); {
		kind, n := refMatch(b[i:], canaries)
		if n == 0 {
			out = append(out, b[i])
			i++
			continue
		}
		out = append(out, red(kind)...)
		fs = append(fs, Finding{Kind: kind, Offset: int64(i)})
		i += n
	}
	return out, fs
}

// ---- helpers ---------------------------------------------------------------

// firstDiff returns the first index where a and b differ, or -1.
func firstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return min(len(a), len(b))
	}
	return -1
}

// kindsOf summarises findings for a failure message: the count and the
// first few kinds.
func kindsOf(fs []Finding) string {
	var ks []string
	for _, f := range fs[:min(len(fs), 5)] {
		ks = append(ks, f.Kind)
	}
	return strconv.Itoa(len(fs)) + " " + strings.Join(ks, ",")
}

// writeChunks writes in through a Writer split at the given cut points and
// returns the output and the reported findings. It fails the test if the
// writer ever holds back more than MaxHold bytes.
func writeChunks(t *testing.T, in []byte, cuts []int, canaries []string) ([]byte, []Finding) {
	t.Helper()
	var out bytes.Buffer
	var fs []Finding
	w := NewWriter(&out, WithCanaries(canaries), WithReport(func(f Finding) { fs = append(fs, f) }))
	prev := 0
	for _, c := range append(cuts, len(in)) {
		if n, err := w.Write(in[prev:c]); err != nil || n != c-prev {
			t.Fatalf("write returned %d, %v; want %d, nil", n, err, c-prev)
		}
		if h := w.held(); h > MaxHold {
			t.Fatalf("writer holds %d bytes, more than MaxHold %d", h, MaxHold)
		}
		prev = c
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return out.Bytes(), fs
}

func oneByteCuts(n int) []int {
	cuts := make([]int, 0, n)
	for i := 1; i < n; i++ {
		cuts = append(cuts, i)
	}
	return cuts
}

// checkAll compares Bytes, Contains and the Writer (whole, one-byte chunks
// and the extra cut sets) with the reference.
func checkAll(t *testing.T, label string, in []byte, canaries []string, cutSets ...[]int) {
	t.Helper()
	want, wantF := ref(in, canaries)
	if got := Bytes(in, WithCanaries(canaries)); !bytes.Equal(got, want) {
		t.Fatalf("%s: Bytes differs from reference at byte %d (len %d, want %d), reference kinds %v", label, firstDiff(got, want), len(got), len(want), kindsOf(wantF))
	}
	if got := Contains(in, WithCanaries(canaries)); !reflect.DeepEqual(got, wantF) {
		t.Fatalf("%s: Contains found %s, reference %s", label, kindsOf(got), kindsOf(wantF))
	}
	for _, cuts := range append(cutSets, nil, oneByteCuts(len(in))) {
		got, gotF := writeChunks(t, in, cuts, canaries)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: writer (%d cuts) differs from reference at byte %d (len %d, want %d), reference kinds %v", label, len(cuts), firstDiff(got, want), len(got), len(want), kindsOf(wantF))
		}
		if !reflect.DeepEqual(gotF, wantF) {
			t.Fatalf("%s: writer (%d cuts) reported %s, reference %s", label, len(cuts), kindsOf(gotF), kindsOf(wantF))
		}
	}
}

// ---- the plan's RED test -----------------------------------------------------

func TestRedact_SplitAcrossChunks(t *testing.T) {
	c := "zcanary-split-" + "0123456789abcdef"
	in := "before " + c + " after"
	for k := 1; k < len(c); k++ {
		cut := len("before ") + k
		var out bytes.Buffer
		w := NewWriter(&out, WithCanaries([]string{c}))
		if _, err := w.Write([]byte(in[:cut])); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(in[cut:])); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), c) {
			t.Fatalf("output still contains canary (split %d bytes into it)", k)
		}
		if want := "before " + red(KindCanary) + " after"; out.String() != want {
			t.Fatalf("split %d: output differs from the expected one at byte %d", k, firstDiff(out.Bytes(), []byte(want)))
		}
	}
}

// ---- each pattern ----------------------------------------------------------

func TestPatterns(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // "" means unchanged
	}{
		{"bearer 16", "Authorization: " + bearer(16) + "\n", "Authorization: " + red(KindBearer) + "\n"},
		{"bearer 40 then quote", `"` + bearer(40) + `"`, `"` + red(KindBearer) + `"`},
		{"bearer 15", "Authorization: " + bearer(15) + "\n", ""},
		{"bearer two spaces", preBearer + " " + cycle(bearerChars, 30), ""},
		{"bearer lowercase scheme (known limit)", "bear" + "er " + cycle(bearerChars, 30), ""},
		{"bearer run ends at comma", bearer(20) + ",x", red(KindBearer) + ",x"},
		{"github ghp 20", "x " + github("p", 20) + " y", "x " + red(KindGitHub) + " y"},
		{"github gho 36", github("o", 36), red(KindGitHub)},
		{"github ghu 20", github("u", 20), red(KindGitHub)},
		{"github ghs 20", github("s", 20), red(KindGitHub)},
		{"github ghr 20", github("r", 20), red(KindGitHub)},
		{"github 19", github("p", 19), ""},
		{"github wrong letter", github("x", 30), ""},
		{"github run ends at dash", github("p", 25) + "-tail", red(KindGitHub) + "-tail"},
		{"github pat-form 20", githubPAT(20), red(KindGitHub)},
		{"github pat-form 82", githubPAT(82) + " ", red(KindGitHub) + " "},
		{"github pat-form 19", githubPAT(19), ""},
		{"aws AKIA 16", "id=" + aws("AKIA", 16) + "\n", "id=" + red(KindAWS) + "\n"},
		{"aws ASIA 16 at end", aws("ASIA", 16), red(KindAWS)},
		{"aws 15", aws("AKIA", 15) + " ", ""},
		{"aws 17", aws("AKIA", 17) + " ", ""},
		{"aws lowercase", "akia" + strings.ToLower(cycle(upperDigits, 16)), ""},
		{"aws lowercase body", "AKIA" + strings.ToLower(cycle(upperDigits, 16)), ""},
		{"aws followed by lowercase", aws("AKIA", 16) + "x", red(KindAWS) + "x"},
		{"aws wrong prefix", aws("AKIB", 16), ""},
		{"slack xoxb 10", slack("b", 10), red(KindSlack)},
		{"slack xoxa xoxp xoxr xoxs", slack("a", 12) + " " + slack("p", 12) + " " + slack("r", 12) + " " + slack("s", 12), red(KindSlack) + " " + red(KindSlack) + " " + red(KindSlack) + " " + red(KindSlack)},
		{"slack 9", slack("b", 9), ""},
		{"slack wrong letter", slack("c", 20), ""},
		{"sk 20", "key " + sk(20), "key " + red(KindSK)},
		{"sk 19", "key " + sk(19), ""},
		{"sk underscore prefix", "sk" + "_" + cycle(b64Chars, 30), ""},
		{"google 35", google(35), red(KindGoogle)},
		{"google 36 whole run", google(36) + ".", red(KindGoogle) + "."},
		{"google 34", google(34), ""},
		{"google lowercase", "aiza" + cycle(b64Chars, 35), ""},
		{"jwt 8 8 8", jwt(8, 8, 8), red(KindJWT)},
		{"jwt long", "cookie " + jwt(36, 120, 43) + "; x", "cookie " + red(KindJWT) + "; x"},
		{"jwt seg1 7", jwt(7, 8, 8), ""},
		{"jwt seg2 7", jwt(8, 7, 8), ""},
		{"jwt seg3 7", jwt(8, 8, 7), ""},
		{"jwt lowercase prefix", "eyj" + cycle(b64Chars, 9) + "." + cycle(b64Chars, 9) + "." + cycle(b64Chars, 9), ""},
		{"jwt confirmed at the cap", jwt(4096-21, 8, 30), red(KindJWT)},
		{"jwt one past the cap", jwt(4096-20, 8, 30), ""},
		{"cfauth to space", cfauth("abc.def") + " x", red(KindCFAuth) + " x"},
		{"cfauth to semicolon", cfauth("abc") + ";x", red(KindCFAuth) + ";x"},
		{"cfauth to double quote", cfauth("abc") + `"`, red(KindCFAuth) + `"`},
		{"cfauth to single quote", cfauth("abc") + `'`, red(KindCFAuth) + `'`},
		{"cfauth to tab", cfauth("abc") + "\tx", red(KindCFAuth) + "\tx"},
		{"cfauth to CR", cfauth("abc") + "\r\n", red(KindCFAuth) + "\r\n"},
		{"cfauth to end", cfauth("a"), red(KindCFAuth)},
		{"cfauth empty", cfauth("") + "; x", ""},
		{"cfauth wrong case", "cf_auth" + "orization=abcdef", ""},
		{"no match plain", "the quick brown fox", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			if want == "" {
				want = tt.in
			}
			if got := Bytes([]byte(tt.in)); string(got) != want {
				t.Fatalf("Bytes differs from the expected output at byte %d (len %d, want %d)", firstDiff(got, []byte(want)), len(got), len(want))
			}
			checkAll(t, tt.name, []byte(tt.in), nil)
		})
	}
}

// ---- PEM --------------------------------------------------------------------

func TestPEM(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // "" means unchanged
	}{
		{"rsa", "a\n" + pemBlock("RSA ") + "\nb", "a\n" + red(KindPEM) + "\nb"},
		{"no label", pemBlock(""), red(KindPEM)},
		{"ec", pemBlock("EC "), red(KindPEM)},
		{"openssh", pemBlock("OPENSSH "), red(KindPEM)},
		{"encrypted", pemBlock("ENCRYPTED "), red(KindPEM)},
		{"two words", pemBlock("DSA X9 "), red(KindPEM)},
		{"after text on the same line", "key: " + pemBlock("RSA ") + " done", "key: " + red(KindPEM) + " done"},
		{"json escaped", `{"k":"` + strings.ReplaceAll(pemBlock("RSA "), "\n", `\n`) + `"}`, `{"k":"` + red(KindPEM) + `"}`},
		{"crlf", strings.ReplaceAll(pemBlock("EC "), "\n", "\r\n") + "\r\n", red(KindPEM) + "\r\n"},
		{"end missing", "a\n" + pemBegins("RSA ") + "\nMIIE" + rep("x", 100) + "\n", "a\n" + red(KindPEM)},
		{"begin only at end", "a " + pemBegins(""), "a " + red(KindPEM)},
		{"two blocks", pemBlock("RSA ") + "\nmid\n" + pemBlock("EC ") + "\ntail", red(KindPEM) + "\nmid\n" + red(KindPEM) + "\ntail"},
		{"two blocks adjacent", pemBlock("") + pemBlock(""), red(KindPEM) + red(KindPEM)},
		{"nested runs to outer end", pemBegins("RSA ") + "\nx\n" + pemBlock("EC ") + "\nsecret body\n" + pemEnds("RSA ") + "\nafter", red(KindPEM) + "\nafter"},
		{"mismatched end runs to eof", pemBegins("RSA ") + "\nbody\n" + pemEnds("EC ") + "\nmore body", red(KindPEM)},
		{"end before begin", pemEnds("RSA ") + "\n" + pemBlock("RSA "), pemEnds("RSA ") + "\n" + red(KindPEM)},
		{"six dashes", "-" + pemBlock("RSA "), "-" + red(KindPEM)},
		{"public key not matched", pemBegin + "PUBLIC KEY-----\nMIIB\n" + pemEnd + "PUBLIC KEY-----", ""},
		{"lowercase label not matched", pemBegin + "rsa " + pemTail + "\nbody", ""},
		{"label 64 bytes", pemBlock(rep("ABCDEFG ", 8)), red(KindPEM)},
		{"label 65 bytes", pemBlock("A" + rep("ABCDEFG ", 8)), ""},
		{"begin with no space", "-----BEG" + "IN" + pemTail, ""},
		{"end marker alone", pemEnds("RSA "), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			if want == "" {
				want = tt.in
			}
			if got := Bytes([]byte(tt.in)); string(got) != want {
				t.Fatalf("Bytes differs from the expected output at byte %d (len %d, want %d)", firstDiff(got, []byte(want)), len(got), len(want))
			}
			checkAll(t, tt.name, []byte(tt.in), nil)
		})
	}
}

func TestPEMMarkersSplitAtEveryByte(t *testing.T) {
	for _, in := range []string{
		"text " + pemBlock("RSA ") + " tail",
		"text " + pemBlock("") + " tail",
		"text " + pemBegins("OPENSSH ") + "\nbody without end",
	} {
		want, _ := ref([]byte(in), nil)
		for cut := 1; cut < len(in); cut++ {
			got, _ := writeChunks(t, []byte(in), []int{cut}, nil)
			if !bytes.Equal(got, want) {
				t.Fatalf("split at %d: writer differs from reference at byte %d", cut, firstDiff(got, want))
			}
			if bytes.Contains(got, []byte("MIIE")) || bytes.Contains(got, []byte(rep("w", 64))) {
				t.Fatalf("split at %d: key body leaked", cut)
			}
		}
	}
}

// ---- writer behaviour --------------------------------------------------------

func TestWriterCloseFlushesTail(t *testing.T) {
	for _, tail := range []string{"gh", preBearer + cycle(bearerChars, 10), "AKIA" + cycle(upperDigits, 16), pemBegin + "RSA PRIV", "zcanary-tail-01"} {
		var out bytes.Buffer
		w := NewWriter(&out, WithCanaries([]string{"zcanary-tail-0123456789"}))
		if _, err := w.Write([]byte("abc " + tail)); err != nil {
			t.Fatal(err)
		}
		if got := out.String(); got != "abc " {
			t.Fatalf("tail of %d bytes: before Close the output has %d bytes, want 4 (the tail must be held)", len(tail), len(got))
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		want, _ := ref([]byte("abc "+tail), []string{"zcanary-tail-0123456789"})
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("tail of %d bytes: after Close the output differs from reference at byte %d", len(tail), firstDiff(out.Bytes(), want))
		}
	}
}

func TestWriterEmitsSafePrefix(t *testing.T) {
	var out bytes.Buffer
	w := NewWriter(&out)
	if _, err := w.Write([]byte("hello world\n")); err != nil {
		t.Fatal(err)
	}
	if out.String() != "hello world\n" {
		t.Fatalf("output has %d bytes before Close, want 12 (nothing to hold)", out.Len())
	}
	// A confirmed run is replaced at once; its continuation is swallowed.
	if _, err := w.Write([]byte(github("p", 20))); err != nil {
		t.Fatal(err)
	}
	if out.String() != "hello world\n"+red(KindGitHub) {
		t.Fatalf("a confirmed open run was not replaced at once (output %d bytes)", out.Len())
	}
	if _, err := w.Write([]byte(cycle(alnumChars, 50) + " end")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "hello world\n"+red(KindGitHub)+" end" {
		t.Fatalf("continuation of the run was not swallowed (output %d bytes)", out.Len())
	}
}

type failWriter struct{ err error }

func (f failWriter) Write(p []byte) (int, error) { return 0, f.err }

func TestWriterErrors(t *testing.T) {
	boom := errors.New("boom")
	w := NewWriter(failWriter{boom})
	if _, err := w.Write([]byte("plain text\n")); !errors.Is(err, boom) {
		t.Fatalf("Write error = %v, want boom", err)
	}
	var out bytes.Buffer
	w = NewWriter(&out)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write after Close error = %v, want ErrClosed", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
}

// ---- canaries and overlaps -----------------------------------------------------

func TestOverlappingMatches(t *testing.T) {
	c1 := "zcan-overlap-" + cycle(alnumChars, 12)
	c2 := c1 + "-longer"
	ghAsCanary := github("p", 24) // a canary that is also a GitHub shape
	tests := []struct {
		name     string
		in       string
		canaries []string
		want     string
	}{
		{"longest canary wins", "<" + c2 + ">", []string{c1, c2}, "<" + red(KindCanary) + ">"},
		{"shorter canary when longer is incomplete", "<" + c1 + "-long>", []string{c1, c2}, "<" + red(KindCanary) + "-long>"},
		{"adjacent canaries", c1 + c1, []string{c1}, red(KindCanary) + red(KindCanary)},
		{"pattern wins tie with canary", ghAsCanary + " ", []string{ghAsCanary}, red(KindGitHub) + " "},
		{"longer pattern run beats canary", ghAsCanary + "MORE ", []string{ghAsCanary}, red(KindGitHub) + " "},
		{"longer canary beats pattern", ghAsCanary + "-x ", []string{ghAsCanary + "-x"}, red(KindCanary) + " "},
		{"canary inside bearer token is swallowed", preBearer + cycle(bearerChars, 20) + c1, []string{c1}, red(KindBearer)},
		{"canary inside pem body", pemBegins("") + "\n" + c1 + "\n" + pemEnds(""), []string{c1}, red(KindPEM)},
		{"leftmost wins over a later longer match", "zc" + c1, []string{"zc" + c1[:12], c1}, red(KindCanary) + c1[12:]},
		{"touching pattern and canary", aws("AKIA", 16) + "-" + c1, []string{c1}, red(KindAWS) + "-" + red(KindCanary)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, _ := ref([]byte(tt.in), tt.canaries)
			if string(want) != tt.want {
				t.Fatalf("reference differs from the expected output at byte %d; fix the test", firstDiff(want, []byte(tt.want)))
			}
			checkAll(t, tt.name, []byte(tt.in), tt.canaries)
		})
	}
}

func TestInvalidUTF8AndNUL(t *testing.T) {
	inputs := []string{
		"\xff" + github("p", 20) + "\x00",
		"\x00\x00" + aws("AKIA", 16) + "\xfe",
		cfauth("a\x00b\xffc\xe2\x82") + ";",
		pemBegins("RSA ") + "\x00\xff\n" + pemEnds("RSA ") + "\xc3",
		"gh\x00p_" + cycle(alnumChars, 30),
		"\xe2\x82" + bearer(16) + "\xe2\x82\xac",
		string([]byte{0xf0, 0x9f, 0x98}) + "zcanary-utf8-123" + "\x00",
	}
	for i, in := range inputs {
		want, _ := ref([]byte(in), []string{"zcanary-utf8-123"})
		if !bytes.Contains(want, []byte("[REDACTED:")) && i != 4 {
			t.Fatalf("input %d: reference found no match; fix the test", i)
		}
		checkAll(t, "binary input", []byte(in), []string{"zcanary-utf8-123"})
	}
	r := rand.New(rand.NewPCG(7, 7))
	b := make([]byte, 1<<16)
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	checkAll(t, "random bytes", b, []string{"zcanary-random-1"}, randomCuts(r, len(b)))
}

func TestWithCanariesIgnoresInvalid(t *testing.T) {
	short := "short-11-ch"
	spaced := "has a space in it"
	in := "a " + short + " b " + spaced + " c"
	if got := string(Bytes([]byte(in), WithCanaries([]string{short, spaced, ""}))); got != in {
		t.Fatalf("invalid canary values changed the output (len %d, want %d)", len(got), len(in))
	}
}

func TestFindingHasNoValueField(t *testing.T) {
	ft := reflect.TypeOf(Finding{})
	if ft.NumField() != 2 || ft.Field(0).Name != "Kind" || ft.Field(1).Name != "Offset" || ft.Field(1).Type.Kind() != reflect.Int64 {
		t.Fatalf("Finding must hold only Kind and Offset, has %d fields", ft.NumField())
	}
}

// ---- property test: every chunking equals the reference ----------------------

// gen builds inputs from pieces chosen to sit on pattern boundaries.
type gen struct {
	r        *rand.Rand
	canaries []string
}

const printable = "abcXYZ019!#$%&()*+,-./:<=>?@[]^_{|}~"

const (
	plainChars = "abcdefgh ABC\n\t;\"'-_=."
	delims     = " .;\"'\t\r\n-_=/"
)

func (g *gen) canary() string {
	b := []byte("zcan-")
	for range 7 + g.r.IntN(30) {
		b = append(b, printable[g.r.IntN(len(printable))])
	}
	return string(b)
}

func (g *gen) secret() string {
	n := func(lo int) int { return lo - 1 + g.r.IntN(4) } // lo-1 .. lo+2
	switch g.r.IntN(13) {
	case 0:
		return bearer(n(16))
	case 1:
		return github(string("pousrx"[g.r.IntN(6)]), n(20))
	case 2:
		return githubPAT(n(20))
	case 3:
		return aws([]string{"AKIA", "ASIA", "AKIB"}[g.r.IntN(3)], 14+g.r.IntN(4))
	case 4:
		return slack(string("abprsc"[g.r.IntN(6)]), n(10))
	case 5:
		return sk(n(20))
	case 6:
		return google(n(35))
	case 7:
		return jwt(n(8), n(8), n(8))
	case 8:
		return cfauth(cycle("ab\x00\xffc", g.r.IntN(4)))
	case 9:
		return pemBlock([]string{"", "RSA ", "EC ", "rsa "}[g.r.IntN(4)])
	case 10:
		return pemBegins([]string{"", "RSA ", "EC "}[g.r.IntN(3)])
	case 11:
		return pemEnds([]string{"", "RSA ", "EC "}[g.r.IntN(3)])
	default:
		return g.canaries[g.r.IntN(len(g.canaries))]
	}
}

var fragments = []string{
	preBearer, "Bear", "gh", "ghp_", "github_", "github_pat_", "AKIA", "ASIA", "AK", "xox", "xoxb-", "sk-", "s",
	"AIza", "eyJ", "ey", ".", preCF, "CF_", pemBegin, pemEnd, pemTail, "PRIV", "-----", "RSA ", "EC ",
}

var runClasses = []string{alnumChars, upperDigits, b64Chars, bearerChars, slackChars, alnumChars + "_"}

func (g *gen) piece() string {
	switch g.r.IntN(12) {
	case 0, 1:
		b := make([]byte, g.r.IntN(12))
		for i := range b {
			b[i] = plainChars[g.r.IntN(len(plainChars))]
		}
		return string(b)
	case 2:
		b := make([]byte, g.r.IntN(6))
		for i := range b {
			b[i] = byte(g.r.IntN(256))
		}
		return string(b)
	case 3, 4:
		return fragments[g.r.IntN(len(fragments))]
	case 5:
		return cycle(runClasses[g.r.IntN(len(runClasses))], g.r.IntN(45))
	case 6, 7:
		return g.secret()
	case 8:
		c := g.canaries[g.r.IntN(len(g.canaries))]
		return c[:g.r.IntN(len(c))]
	case 9:
		c := g.canaries[g.r.IntN(len(g.canaries))]
		return c[g.r.IntN(len(c)):]
	case 10:
		return string(delims[g.r.IntN(len(delims))])
	default:
		if g.r.IntN(100) == 0 { // rare: runs around the 4096-byte confirmation cap
			return "ey" + "J" + cycle(b64Chars, 4070+g.r.IntN(30)) + "." + cycle(b64Chars, 8) + "." + cycle(b64Chars, 9)
		}
		return g.canaries[g.r.IntN(len(g.canaries))]
	}
}

func randomCuts(r *rand.Rand, n int) []int {
	if n < 2 {
		return nil
	}
	var cuts []int
	for i := 1; i < n; i++ {
		if r.IntN(1+r.IntN(40)) == 0 {
			cuts = append(cuts, i)
		}
	}
	return cuts
}

func TestWriterMatchesReferenceOnRandomChunkings(t *testing.T) {
	const trials = 2000
	seen := map[string]int{}
	for seed := uint64(1); seed <= trials; seed++ {
		r := rand.New(rand.NewPCG(seed, 0x10))
		g := &gen{r: r}
		c1 := g.canary()
		g.canaries = []string{c1, c1 + "-ext", c1[:8] + "!other", github("p", 24), sk(22) + "~"}
		if seed%50 == 0 {
			g.canaries = append(g.canaries, "zcan-"+cycle(printable, 251))
		}
		var sb strings.Builder
		for range 1 + r.IntN(40) {
			sb.WriteString(g.piece())
		}
		in := []byte(sb.String())
		_, wantF := ref(in, g.canaries)
		for _, f := range wantF {
			seen[f.Kind]++
		}
		checkAll(t, "seed "+strconv.FormatUint(seed, 10), in, g.canaries, randomCuts(r, len(in)), randomCuts(r, len(in)))
		if t.Failed() {
			return
		}
	}
	for _, k := range []string{KindPEM, KindBearer, KindGitHub, KindAWS, KindSlack, KindSK, KindGoogle, KindJWT, KindCFAuth, KindCanary} {
		if seen[k] < 20 {
			t.Errorf("kind %s matched in only %d places across the trials; the generator is too weak", k, seen[k])
		}
	}
}

// ---- size ----------------------------------------------------------------------

func TestMillionByteInput(t *testing.T) {
	c := "zcanary-million-0001"
	secrets := []string{bearer(30), github("p", 36), githubPAT(60), aws("AKIA", 16), slack("b", 20), sk(40), google(35), jwt(20, 40, 30), cfauth("v1.abc"), pemBlock("RSA "), c}
	var sb strings.Builder
	for i := 0; sb.Len() < 1_000_000; i++ {
		sb.WriteString("line of ordinary log text with some words ")
		if i%7 == 0 {
			sb.WriteString(secrets[i%len(secrets)])
		}
		sb.WriteString("\n")
	}
	in := []byte(sb.String()[:1_000_000])
	r := rand.New(rand.NewPCG(1, 2))
	checkAll(t, "million", in, []string{c}, randomCuts(r, len(in)))
	out := Bytes(in, WithCanaries([]string{c}))
	for _, s := range secrets[:len(secrets)-2] {
		if bytes.Contains(out, []byte(s)) {
			t.Fatalf("a secret of %d bytes survived in the output", len(s))
		}
	}
	if bytes.Contains(out, []byte(c)) {
		t.Fatal("output still contains canary")
	}
}

type compareSink struct {
	want []byte
	off  int
	bad  int
}

func (s *compareSink) Write(p []byte) (int, error) {
	if s.bad < 0 && !bytes.Equal(p, s.want[s.off:min(len(s.want), s.off+len(p))]) {
		s.bad = s.off
	}
	s.off += len(p)
	return len(p), nil
}

func TestTenMiBWithoutMatchStreamsInBoundedMemory(t *testing.T) {
	line := []byte("the quick brown fox jumps over the lazy dog 0123456789 -- ok\n")
	in := bytes.Repeat(line, (10<<20)/len(line)+1)[:10<<20]
	sink := &compareSink{want: in, bad: -1}
	w := NewWriter(sink, WithCanaries([]string{"zcanary-tenmib-01"}))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for off := 0; off < len(in); off += 64 << 10 {
		if _, err := w.Write(in[off:min(len(in), off+64<<10)]); err != nil {
			t.Fatal(err)
		}
		if h, c := w.held(), w.bufCap(); h > MaxHold || c > MaxHold+feedStep {
			t.Fatalf("after %d bytes the writer holds %d bytes with buffer capacity %d", off, h, c)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if sink.bad >= 0 || sink.off != len(in) {
		t.Fatalf("output differs from input at byte %d (wrote %d of %d)", sink.bad, sink.off, len(in))
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Fatalf("writer allocated %d bytes for 10 MiB of input", alloc)
	}
}

func TestHoldNeverExceedsMaxHold(t *testing.T) {
	inputs := []string{
		"ey" + "J" + cycle(b64Chars, 5000),
		"ey" + "J" + cycle(b64Chars, 4080) + "." + cycle(b64Chars, 20),
		pemBegins("RSA ") + rep("A", 20000),
		pemBegin + rep("AB ", 30),
		rep("zcan-", 200),
		preCF + rep("x", 9000),
	}
	r := rand.New(rand.NewPCG(3, 4))
	for _, in := range inputs {
		writeChunks(t, []byte(in), randomCuts(r, len(in)), []string{"zcan-" + cycle(printable, 251)})
		writeChunks(t, []byte(in), oneByteCuts(len(in)), []string{"zcan-" + cycle(printable, 251)})
	}
}

// ---- our own sources -------------------------------------------------------------

// TestSourcesHaveNoSecretShapes keeps the files of this task free of complete
// secret-shaped literals, so later secret scanners stay green on them.
func TestSourcesHaveNoSecretShapes(t *testing.T) {
	var files []string
	for _, dir := range []string{".", "../../tools/evidencescan", "../../tests/support/canary"} {
		m, err := filepath.Glob(filepath.Join(dir, "*"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 5 {
		t.Fatalf("found only %d files to check", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if fs := Contains(b); len(fs) > 0 {
			t.Errorf("%s: %d secret-shaped strings, first %s at offset %d", f, len(fs), fs[0].Kind, fs[0].Offset)
		}
	}
}
