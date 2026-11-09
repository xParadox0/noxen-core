// Package redact is the shared redaction and canary detection used by the
// runner, the control-plane logger and the evidence scanner.
//
// Bytes, Contains and Writer share one engine, so a Writer's output is
// byte-identical to Bytes on the concatenated input for every way the input
// is split into writes. The engine scans left to right; at each position it
// takes the longest match there (a pattern wins a tie with a canary),
// replaces it with "[REDACTED:<kind>]" and continues after it. Matches that
// overlap or touch are therefore resolved leftmost first, then longest.
// A Finding carries the kind and the byte offset only, never the value.
//
// The pattern set is shape-based and was written from memory. None of the
// provider formats below has been checked against provider documentation;
// a provider can change its format, and formats that are not listed are not
// caught.
//
//	pem     "-----BEGIN <LABEL>PRIVATE KEY-----" through the first
//	        "-----END <LABEL>PRIVATE KEY-----" with the same label, or
//	        through the end of the input when that END marker never comes.
//	        LABEL is zero or more words of [A-Z0-9], each followed by one
//	        space, 64 bytes at most. The markers may appear anywhere, not
//	        only at the start of a line.
//	bearer  "Bearer " then 16 or more of [A-Za-z0-9._~+/=-]
//	github  "ghp_", "gho_", "ghu_", "ghs_" or "ghr_" then 20 or more of
//	        [A-Za-z0-9]; "github_pat_" then 20 or more of [A-Za-z0-9_]
//	aws     "AKIA" or "ASIA" then exactly 16 of [0-9A-Z], not followed by
//	        another [0-9A-Z]
//	slack   "xoxa-", "xoxb-", "xoxp-", "xoxr-" or "xoxs-" then 10 or more
//	        of [A-Za-z0-9-]
//	sk      "sk-" then 20 or more of [A-Za-z0-9_-]
//	google  "AIza" then 35 or more of [A-Za-z0-9_-]
//	jwt     "eyJ" then 8 or more of [A-Za-z0-9_-], ".", 8 or more, ".",
//	        8 or more; this covers Cloudflare Access tokens
//	cfauth  "CF_Authorization=" then one or more bytes up to the next
//	        whitespace, ";", '"' or "'" (the name is part of the match)
//	canary  a value registered with WithCanaries, byte for byte
//
// A run ("or more") is taken whole, however long. A match must be confirmed
// within MaxHold bytes of its start: only the jwt shape can need that many
// (a jwt whose first two parts are longer is not caught). Matching is on
// bytes; invalid UTF-8 and NUL bytes neither panic nor change how the
// ASCII shapes match. No pattern looks at the byte before its start.
//
// Streaming: a Writer holds back fewer than MaxHold bytes, only while a
// match could still start in them. Once a match is certain its marker is
// written at once; the rest of a run, or of a PEM block up to its END
// marker, is discarded as it arrives, so a long or unterminated block is
// never buffered and never written.
package redact

import (
	"errors"
	"io"
)

// MaxHold bounds the bytes a Writer holds back between writes.
const MaxHold = 4096

// feedStep is the most input bytes the engine buffers per step.
const feedStep = 32 << 10

// Kinds of match.
const (
	KindPEM    = "pem"
	KindBearer = "bearer"
	KindGitHub = "github"
	KindAWS    = "aws"
	KindSlack  = "slack"
	KindSK     = "sk"
	KindGoogle = "google"
	KindJWT    = "jwt"
	KindCFAuth = "cfauth"
	KindCanary = "canary"
)

// ErrClosed is returned by Write after Close.
var ErrClosed = errors.New("redact: write after close")

// Finding is one match: its kind and the byte offset in the input where it
// starts. It never holds the matched text.
type Finding struct {
	Kind   string
	Offset int64
}

// Option configures redaction.
type Option func(*config)

type config struct {
	canaries []string
	report   func(Finding)
}

// WithCanaries adds registered canary values. Values that fail ValidCanary
// (fewer than 12 or more than 256 bytes, a byte outside printable ASCII, a
// space, a leading "#") are ignored: validate them first with ValidCanary or
// ParseCanaries.
func WithCanaries(values []string) Option {
	return func(c *config) {
		for _, v := range values {
			if ValidCanary(v) == nil {
				c.canaries = append(c.canaries, v)
			}
		}
	}
}

// WithReport calls fn for every match, in input order, as soon as the match
// is certain.
func WithReport(fn func(Finding)) Option {
	return func(c *config) {
		if prev := c.report; prev != nil {
			c.report = func(f Finding) { prev(f); fn(f) }
		} else {
			c.report = fn
		}
	}
}

// Bytes returns b with every match replaced by "[REDACTED:<kind>]".
func Bytes(b []byte, opts ...Option) []byte {
	out := make([]byte, 0, len(b))
	e := newEngine(opts, func(p []byte) error { out = append(out, p...); return nil })
	_ = e.feed(b) // the sink never fails
	_ = e.step(true)
	return out
}

// Contains returns the matches in b, in order.
func Contains(b []byte, opts ...Option) []Finding {
	var fs []Finding
	opts = append(opts[:len(opts):len(opts)], WithReport(func(f Finding) { fs = append(fs, f) }))
	e := newEngine(opts, func([]byte) error { return nil })
	_ = e.feed(b)
	_ = e.step(true)
	return fs
}

// Writer redacts what is written to it and writes the result to the
// underlying writer. It holds back fewer than MaxHold bytes between writes;
// Close writes the held tail. Close does not close the underlying writer.
// A Writer is not safe for concurrent use.
type Writer struct {
	e      *engine
	err    error
	closed bool
}

// NewWriter returns a redacting writer over w.
func NewWriter(w io.Writer, opts ...Option) *Writer {
	return &Writer{e: newEngine(opts, func(p []byte) error {
		n, err := w.Write(p)
		if err == nil && n < len(p) {
			err = io.ErrShortWrite
		}
		return err
	})}
}

// Write redacts p. An error from the underlying writer is returned by this
// and every later call.
func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, ErrClosed
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.err = w.e.feed(p); w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

// Close decides the held tail at end of input and writes it: an incomplete
// prefix is written as it is, an unterminated PEM block stays discarded.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	w.err = w.e.step(true)
	return w.err
}

func (w *Writer) held() int   { return len(w.e.buf) }
func (w *Writer) bufCap() int { return cap(w.e.buf) }

// Engine modes.
const (
	scanning = iota
	inRun    // discarding the rest of a confirmed run
	inPEM    // discarding a PEM block up to its END marker
)

type engine struct {
	first    [256]bool     // bytes where a match can start
	canaries [256][]string // by first byte
	report   func(Finding)
	emit     func([]byte) error

	buf  []byte // undecided input; buf[0] is at stream offset base
	base int64
	mode int
	run  *class // inRun
	end  []byte // inPEM
}

func newEngine(opts []Option, emit func([]byte) error) *engine {
	var c config
	for _, o := range opts {
		o(&c)
	}
	e := &engine{report: c.report, emit: emit}
	for i, fs := range matchers {
		e.first[i] = len(fs) > 0
	}
	seen := map[string]bool{}
	for _, v := range c.canaries {
		if !seen[v] {
			seen[v] = true
			e.canaries[v[0]] = append(e.canaries[v[0]], v)
			e.first[v[0]] = true
		}
	}
	return e
}

// feed appends p in steps of at most feedStep bytes, deciding as it goes.
func (e *engine) feed(p []byte) error {
	for len(p) > 0 {
		n := min(len(p), feedStep)
		if len(e.buf)+n > cap(e.buf) {
			// Grow to what is needed, at most MaxHold+feedStep, instead of
			// letting append double past that bound.
			c := max(min(2*cap(e.buf), MaxHold+feedStep), len(e.buf)+n)
			nb := make([]byte, len(e.buf), c)
			copy(nb, e.buf)
			e.buf = nb
		}
		e.buf = append(e.buf, p[:n]...)
		p = p[n:]
		if err := e.step(false); err != nil {
			return err
		}
	}
	return nil
}

// matchAt decides the match at the start of b. It returns needMore only
// when eof is false and more input could change the decision.
func (e *engine) matchAt(b []byte, eof bool) match {
	var best match
	pending := false
	for _, f := range matchers[b[0]] {
		switch m := f(b, eof); m.res {
		case needMore:
			pending = true
		case fixed, open:
			best = m
		}
	}
	for _, c := range e.canaries[b[0]] {
		switch prefixAt(b, c, eof) {
		case needMore:
			pending = true
		case fixed:
			// An open run is at least len(b) >= len(c) long and wins a tie;
			// a PEM block cannot share a start with a canary (its marker
			// has a space at index 10, a canary has none).
			if best.res == none || best.res == fixed && best.kind != KindPEM && len(c) > best.n {
				best = match{res: fixed, kind: KindCanary, n: len(c)}
			}
		}
	}
	if pending {
		return match{res: needMore}
	}
	return best
}

func (e *engine) out(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	return e.emit(p)
}

// step decides as much of buf as it can and drops what it decided. With
// eof it decides everything.
func (e *engine) step(eof bool) error {
	s := 0 // buf[:s] is decided
	defer func() {
		e.base += int64(s)
		e.buf = e.buf[:copy(e.buf, e.buf[s:])]
	}()
loop:
	for s < len(e.buf) {
		switch e.mode {
		case inRun:
			s += runLen(e.buf, s, e.run, -1)
			if s == len(e.buf) {
				break loop
			}
			e.mode = scanning
		case inPEM:
			if k := pemBodyEnd(e.buf[s:], e.end); k >= 0 {
				s += k
				e.mode = scanning
				continue
			}
			keep := len(e.end) - 1 // a partial END marker
			if eof {
				keep = 0
			}
			s = max(s, len(e.buf)-keep)
			break loop
		default:
			for i := s; i < len(e.buf); i++ {
				if !e.first[e.buf[i]] {
					continue
				}
				m := e.matchAt(e.buf[i:], eof)
				if m.res == none {
					continue
				}
				if err := e.out(e.buf[s:i]); err != nil {
					return err
				}
				s = i
				if m.res == needMore {
					break loop
				}
				if err := e.out([]byte("[REDACTED:" + m.kind + "]")); err != nil {
					return err
				}
				if e.report != nil {
					e.report(Finding{Kind: m.kind, Offset: e.base + int64(i)})
				}
				switch {
				case m.kind == KindPEM:
					e.mode, e.end, s = inPEM, m.end, i+m.n
				case m.res == open:
					e.mode, e.run, s = inRun, m.cls, len(e.buf)
				default:
					s = i + m.n
				}
				continue loop
			}
			if err := e.out(e.buf[s:]); err != nil {
				return err
			}
			s = len(e.buf)
		}
	}
	return nil
}
