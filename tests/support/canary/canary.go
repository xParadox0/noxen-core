// Package canary makes synthetic canary values and registers them with the
// redaction scanner.
//
// A value from New is "NXCANARY-<kind>-" followed by 32 lowercase hex digits
// from crypto/rand: unique, obviously synthetic, and not the shape of any
// real credential. Tests put it where a secret or a piece of plaintext would
// go, and then assert it shows up nowhere it must not (HLD §20.3). Register
// appends it to a registry file, which tools/evidencescan reads; values in
// the registry are redacted as [REDACTED:canary].
package canary

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"chronyxlabs.com/noxen-studio/internal/redact"
)

// Prefix starts every value from New.
const Prefix = "NXCANARY-"

// New returns a fresh canary value for kind, which must be 1 to 32 bytes of
// [a-z0-9]; any other kind is a programming error and panics.
func New(kind string) string {
	if !validKind(kind) {
		panic("canary: kind must be 1 to 32 bytes of [a-z0-9]")
	}
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error
	return Prefix + kind + "-" + hex.EncodeToString(b[:])
}

func validKind(kind string) bool {
	if len(kind) == 0 || len(kind) > 32 {
		return false
	}
	for i := 0; i < len(kind); i++ {
		if c := kind[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// Register appends value as one line to the registry at path, creating the
// file with mode 0600 if needed (an existing file keeps its mode). A value
// that fails redact.ValidCanary is rejected before the file is touched. If
// the file does not end with a newline, one is added first. Register does
// not lock the file; concurrent callers must serialize.
func Register(path, value string) (err error) {
	if err := redact.ValidCanary(value); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Clean(path), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	line := value + "\n"
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if size := info.Size(); size > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], size-1); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if last[0] != '\n' {
			line = "\n" + line
		}
	}
	_, err = f.WriteString(line)
	return err
}
