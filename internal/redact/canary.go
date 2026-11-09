package redact

import (
	"bytes"
	"errors"
	"fmt"
)

// Canary value bounds.
const (
	MinCanary = 12
	MaxCanary = 256
)

var errCanary = errors.New("canary must be 12 to 256 bytes of printable ASCII without spaces, not starting with #")

// ValidCanary checks a canary value: 12 to 256 bytes, each printable ASCII
// other than space (0x21 to 0x7e), and not starting with "#" (a registry
// would read that line as a comment). The error never contains the value.
func ValidCanary(v string) error {
	if len(v) < MinCanary || len(v) > MaxCanary || v[0] == '#' {
		return errCanary
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return errCanary
		}
	}
	return nil
}

// ParseCanaries reads a canary registry: one value per line, a trailing CR
// ignored, blank lines and lines whose first non-blank byte is "#" skipped,
// duplicates dropped, file order kept. A line that is not a valid value is
// an error naming its line number only, never its content.
func ParseCanaries(data []byte) ([]string, error) {
	var vals []string
	seen := map[string]bool{}
	for i, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if t := bytes.TrimLeft(line, " \t"); len(bytes.TrimSpace(t)) == 0 || t[0] == '#' {
			continue
		}
		v := string(line)
		if err := ValidCanary(v); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if !seen[v] {
			seen[v] = true
			vals = append(vals, v)
		}
	}
	return vals, nil
}
