package redact

import "bytes"

// result is a matcher's decision at one position.
type result uint8

const (
	none     result = iota
	needMore        // the data so far cannot decide; more input can
	fixed           // a match of known length n
	open            // a confirmed match that reaches the end of the data and continues over cls
)

// match is a decision with what the engine needs to act on it.
type match struct {
	res  result
	kind string
	n    int    // length for fixed; len(data) for open
	cls  *class // open: the class that continues the match
	end  []byte // pem: the END marker that closes the block
}

// maxLabel bounds the PEM label, so the BEGIN marker is at most
// 11+maxLabel+16 bytes.
const maxLabel = 64

type class [256]bool

func classOf(chars string) *class {
	var c class
	for i := 0; i < len(chars); i++ {
		c[chars[i]] = true
	}
	return &c
}

func classExcept(chars string) *class {
	c := classOf(chars)
	for i := range c {
		c[i] = !c[i]
	}
	return c
}

const (
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower  = "abcdefghijklmnopqrstuvwxyz"
	digits = "0123456789"
)

var (
	alnumClass  = classOf(upper + lower + digits)
	patClass    = classOf(upper + lower + digits + "_")
	b64urlClass = classOf(upper + lower + digits + "_-")
	bearerClass = classOf(upper + lower + digits + "._~+/=-")
	slackClass  = classOf(upper + lower + digits + "-")
	upperDigit  = classOf(upper + digits)
	cfValue     = classExcept(" \t\n\v\f\r;\"'")
)

// The patterns are listed in the package documentation.

// runPat is a literal prefix followed by a run of at least min bytes of cls.
type runPat struct {
	kind     string
	prefixes []string
	cls      *class
	min      int
}

var runPats = []runPat{
	{KindBearer, []string{"Bearer "}, bearerClass, 16},
	{KindGitHub, []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, alnumClass, 20},
	{KindGitHub, []string{"github_pat_"}, patClass, 20},
	{KindSlack, []string{"xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"}, slackClass, 10},
	{KindSK, []string{"sk-"}, b64urlClass, 20},
	{KindGoogle, []string{"AIza"}, b64urlClass, 35},
	{KindCFAuth, []string{"CF_Authorization="}, cfValue, 1},
}

// matchers lists, by first byte, the pattern matchers that can start there.
// No pattern prefix is a prefix of another, so at most one of them can
// match at a position.
var matchers [256][]func(b []byte, eof bool) match

func init() {
	add := func(first byte, f func([]byte, bool) match) { matchers[first] = append(matchers[first], f) }
	add('-', matchPEM)
	add('A', matchAWS)
	add('e', matchJWT)
	for i := range runPats {
		p := &runPats[i]
		seen := map[byte]bool{}
		for _, pre := range p.prefixes {
			if !seen[pre[0]] {
				seen[pre[0]] = true
				add(pre[0], func(b []byte, eof bool) match { return matchRun(b, eof, p) })
			}
		}
	}
}

// prefixAt says whether b starts with lit (fixed), could still once more
// data arrives (needMore), or cannot (none).
func prefixAt(b []byte, lit string, eof bool) result {
	if len(b) >= len(lit) {
		if string(b[:len(lit)]) == lit {
			return fixed
		}
		return none
	}
	if !eof && string(b) == lit[:len(b)] {
		return needMore
	}
	return none
}

// runLen counts the bytes of cls in b from index from, stopping at limit
// bytes when limit >= 0.
func runLen(b []byte, from int, cls *class, limit int) int {
	k := 0
	for from+k < len(b) && cls[b[from+k]] && (limit < 0 || k < limit) {
		k++
	}
	return k
}

func matchRun(b []byte, eof bool, p *runPat) match {
	res := none
	for _, pre := range p.prefixes {
		switch prefixAt(b, pre, eof) {
		case needMore:
			res = needMore
		case fixed:
			k := runLen(b, len(pre), p.cls, -1)
			end := len(pre) + k
			switch {
			case end < len(b) || eof:
				if k >= p.min {
					return match{res: fixed, kind: p.kind, n: end}
				}
				return match{}
			case k >= p.min:
				return match{res: open, kind: p.kind, n: len(b), cls: p.cls}
			default:
				return match{res: needMore}
			}
		}
	}
	return match{res: res}
}

func matchAWS(b []byte, eof bool) match {
	res := none
	for _, pre := range []string{"AKIA", "ASIA"} {
		switch prefixAt(b, pre, eof) {
		case needMore:
			res = needMore
		case fixed:
			k := runLen(b, 4, upperDigit, 17)
			switch {
			case k > 16:
				return match{}
			case 4+k == len(b) && !eof:
				return match{res: needMore}
			case k == 16:
				return match{res: fixed, kind: KindAWS, n: 20}
			default:
				return match{}
			}
		}
	}
	return match{res: res}
}

func matchJWT(b []byte, eof bool) match {
	if r := prefixAt(b, "eyJ", eof); r != fixed {
		return match{res: r}
	}
	// Confirmation must fit in the first MaxHold bytes.
	w, weof := b, eof
	if len(w) >= MaxHold {
		w, weof = w[:MaxHold], true
	}
	p := 3
	for range 2 {
		k := runLen(w, p, b64urlClass, -1)
		p += k
		if p == len(w) {
			if weof {
				return match{}
			}
			return match{res: needMore}
		}
		if k < 8 || w[p] != '.' {
			return match{}
		}
		p++
	}
	if k := runLen(w, p, b64urlClass, 8); k < 8 {
		if p+k == len(w) && !weof {
			return match{res: needMore}
		}
		return match{}
	}
	end := p + runLen(b, p, b64urlClass, -1)
	if end == len(b) && !eof {
		return match{res: open, kind: KindJWT, n: len(b), cls: b64urlClass}
	}
	return match{res: fixed, kind: KindJWT, n: end}
}

const (
	pemBeginPrefix = "-----BEGIN "
	pemEndPrefix   = "-----END "
	pemSuffix      = "PRIVATE KEY-----"
)

// matchPEM matches the BEGIN marker; the engine then discards everything up
// to the END marker it returns.
func matchPEM(b []byte, eof bool) match {
	if r := prefixAt(b, pemBeginPrefix, eof); r != fixed {
		return match{res: r}
	}
	p := len(pemBeginPrefix)
	for {
		switch prefixAt(b[p:], pemSuffix, eof) {
		case fixed:
			end := make([]byte, 0, len(pemEndPrefix)+p-len(pemBeginPrefix)+len(pemSuffix))
			end = append(append(append(end, pemEndPrefix...), b[len(pemBeginPrefix):p]...), pemSuffix...)
			return match{res: fixed, kind: KindPEM, n: p + len(pemSuffix), end: end}
		case needMore:
			return match{res: needMore}
		}
		// Not the suffix here, so a label word and its space must follow.
		k := runLen(b, p, upperDigit, maxLabel+1)
		if p+k+1-len(pemBeginPrefix) > maxLabel {
			return match{}
		}
		if p+k == len(b) {
			if eof {
				return match{}
			}
			return match{res: needMore}
		}
		if k == 0 || b[p+k] != ' ' {
			return match{}
		}
		p += k + 1
	}
}

// pemBodyEnd finds the END marker in b; it returns the index just past it,
// or -1.
func pemBodyEnd(b, end []byte) int {
	if k := bytes.Index(b, end); k >= 0 {
		return k + len(end)
	}
	return -1
}
