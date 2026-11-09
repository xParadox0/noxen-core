package depscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

const (
	// maxInlineKey is the longest key kept as text; a longer key is kept as
	// its SHA-256, so a huge key costs 32 bytes of memory, not its length.
	maxInlineKey = 64
)

// maxKeys bounds the key sets of one document. It is a variable only so a
// test can lower it.
var maxKeys = 2_000_000

// dupKeyError reports an object that holds the same key twice. It names the
// kind of input and a byte offset, never the key or a value.
type dupKeyError struct {
	what string
	off  int64
}

func (e *dupKeyError) Error() string {
	return fmt.Sprintf("duplicate key in %s at byte offset %d", e.what, e.off)
}

// wrapScan prefixes a decoding error with the kind of input. A duplicate key
// error already names it and is returned as it is.
func wrapScan(what string, err error) error {
	var d *dupKeyError
	if errors.As(err, &d) {
		return err
	}
	return fmt.Errorf("%s: %w", what, err)
}

// foldKey maps a key to the smallest rune of each rune's case-folding orbit,
// so two keys are equal under strings.EqualFold exactly when their folded
// forms are equal. encoding/json matches struct fields case-insensitively,
// so two keys that differ only in case would be merged by the policy decoder.
func foldKey(s string) string {
	return strings.Map(func(r rune) rune {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		return m
	}, s)
}

// keyID is the set member for a (folded) key.
func keyID(folded string) string {
	if len(folded) <= maxInlineKey {
		return "k" + folded
	}
	sum := sha256.Sum256([]byte(folded))
	return "h" + string(sum[:])
}

type keyFrame struct {
	obj     bool
	wantKey bool
	keys    map[string]struct{}
}

// checkKeys walks the first JSON value of data with Decoder.Token and returns
// a *dupKeyError when any object, at any depth, holds two keys that are equal
// or equal under case-folding. base is the offset of data in the whole input.
// Syntax errors are returned too, mapped like the policy decoder's. Empty data
// is not an error here: the policy decoder reports it. The walk is linear in
// the input, keeps a stack as deep as the document and one small entry per
// key.
func checkKeys(data []byte, base int64, what string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []keyFrame
	tracked := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(stack) == 0 {
					return nil
				}
				return errTruncated
			}
			return decodeErr(err)
		}
		top := len(stack) - 1
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				f := keyFrame{obj: d == '{', wantKey: d == '{'}
				if f.obj {
					f.keys = map[string]struct{}{}
				}
				stack = append(stack, f)
			default:
				stack = stack[:top]
				if top > 0 && stack[top-1].obj {
					stack[top-1].wantKey = true
				}
			}
		} else if top >= 0 && stack[top].obj {
			f := &stack[top]
			if f.wantKey {
				s, _ := tok.(string)
				tracked++
				if tracked > maxKeys {
					return fmt.Errorf("more than %d object keys in %s", maxKeys, what)
				}
				id := keyID(foldKey(s))
				if _, dup := f.keys[id]; dup {
					return &dupKeyError{what: what, off: base + dec.InputOffset()}
				}
				f.keys[id] = struct{}{}
			}
			f.wantKey = !f.wantKey
		}
		if len(stack) == 0 {
			return nil
		}
	}
}
