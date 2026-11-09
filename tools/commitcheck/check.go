// Package commitcheck enforces the TDD commit rules:
//
//   - the subject is at most 72 characters;
//   - the final paragraph carries exactly one "TDD-Phase: red" or
//     "TDD-Phase: green" trailer and a "Refs:" trailer listing IDs such as
//     "T0.02, PRD-D8";
//   - only red commits may contain failing tests;
//   - changes under visual snapshot directories need a non-empty
//     "Visual-Baseline-Approved:" trailer.
//
// Trailers follow git: they are "Key: value" lines in the final paragraph
// of the message, which cannot be the subject paragraph. Keys match
// case-insensitively.
package commitcheck

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxSubject is the longest allowed subject, in characters.
const MaxSubject = 72

// Rule violations reported by Check.
var (
	ErrEmptySubject       = errors.New("empty subject")
	ErrSubjectTooLong     = errors.New("subject too long")
	ErrMissingPhase       = errors.New("missing TDD-Phase trailer")
	ErrInvalidPhase       = errors.New("invalid TDD-Phase trailer")
	ErrMissingRefs        = errors.New("missing Refs trailer")
	ErrInvalidRefs        = errors.New("invalid Refs trailer")
	ErrFailingTests       = errors.New("tests fail")
	ErrUnapprovedSnapshot = errors.New("snapshot change without Visual-Baseline-Approved trailer")
)

// Commit is a commit about to be recorded.
type Commit struct {
	// Message is the raw message as git hands it to the commit-msg hook.
	// Lines starting with '#' and everything below the scissors line of
	// "git commit -v" are ignored.
	Message string
	// Paths are the repository-relative paths the commit adds, modifies or
	// deletes.
	Paths []string
	// RunTests runs the tests against the tree being committed and returns
	// an error describing any failure. Check calls it for green commits
	// only; a green commit without RunTests is rejected.
	RunTests func() error
}

const (
	phaseKey    = "tdd-phase"
	refsKey     = "refs"
	approvalKey = "visual-baseline-approved"
	scissors    = "------------------------ >8 ------------------------"
)

var (
	trailerLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*(.*)$`)
	refID       = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:[.-][A-Z0-9]+)*$`)
)

// Check returns nil if c satisfies every commit rule. Otherwise it returns
// all violations joined; each wraps one of the Err* values.
func Check(c Commit) error {
	subject, trailers := parse(c.Message)
	var errs []error

	switch n := utf8.RuneCountInString(subject); {
	case n == 0:
		errs = append(errs, ErrEmptySubject)
	case n > MaxSubject:
		errs = append(errs, fmt.Errorf("%w: %d characters, at most %d allowed", ErrSubjectTooLong, n, MaxSubject))
	}

	phases := trailers[phaseKey]
	phase := ""
	switch {
	case len(phases) == 0:
		errs = append(errs, ErrMissingPhase)
	case len(phases) > 1:
		errs = append(errs, fmt.Errorf("%w: given %d times, want exactly one", ErrInvalidPhase, len(phases)))
	case phases[0] != "red" && phases[0] != "green":
		errs = append(errs, fmt.Errorf("%w: %q, want red or green", ErrInvalidPhase, phases[0]))
	default:
		phase = phases[0]
	}

	refs := trailers[refsKey]
	if len(refs) == 0 {
		errs = append(errs, ErrMissingRefs)
	}
	for _, r := range refs {
		for _, id := range strings.Split(r, ",") {
			if id = strings.TrimSpace(id); !refID.MatchString(id) {
				errs = append(errs, fmt.Errorf("%w: %q is not an ID such as T0.02 or PRD-D8", ErrInvalidRefs, id))
			}
		}
	}

	if snaps := snapshotPaths(c.Paths); len(snaps) > 0 && !approved(trailers[approvalKey]) {
		errs = append(errs, fmt.Errorf("%w: %s", ErrUnapprovedSnapshot, strings.Join(snaps, ", ")))
	}

	if phase == "green" {
		if c.RunTests == nil {
			errs = append(errs, fmt.Errorf("%w: green commit was not tested", ErrFailingTests))
		} else if err := c.RunTests(); err != nil {
			errs = append(errs, fmt.Errorf("%w; only TDD-Phase: red may commit failing tests: %w", ErrFailingTests, err))
		}
	}

	return errors.Join(errs...)
}

// parse returns the subject and the trailers of msg, keyed by lower-case
// trailer key.
func parse(msg string) (string, map[string][]string) {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(msg, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "#") {
			if strings.TrimSpace(line[1:]) == scissors {
				break
			}
			continue
		}
		lines = append(lines, strings.TrimRight(line, " \t"))
	}

	var paragraphs [][]string
	var cur []string
	for _, line := range append(lines, "") {
		if line != "" {
			cur = append(cur, line)
		} else if cur != nil {
			paragraphs = append(paragraphs, cur)
			cur = nil
		}
	}

	trailers := map[string][]string{}
	if len(paragraphs) == 0 {
		return "", trailers
	}
	if len(paragraphs) > 1 {
		for _, line := range paragraphs[len(paragraphs)-1] {
			if m := trailerLine.FindStringSubmatch(line); m != nil {
				key := strings.ToLower(m[1])
				trailers[key] = append(trailers[key], m[2])
			}
		}
	}
	return paragraphs[0][0], trailers
}

// snapshotPaths returns the paths that lie in a visual snapshot directory:
// Playwright's "<spec>-snapshots", Jest/Vitest "__snapshots__" or Vitest
// browser mode "__screenshots__".
func snapshotPaths(paths []string) []string {
	var snaps []string
	for _, p := range paths {
		dirs := strings.Split(p, "/")
		for _, d := range dirs[:len(dirs)-1] {
			if d == "__snapshots__" || d == "__screenshots__" || strings.HasSuffix(d, "-snapshots") {
				snaps = append(snaps, p)
				break
			}
		}
	}
	return snaps
}

func approved(values []string) bool {
	for _, v := range values {
		if v != "" {
			return true
		}
	}
	return false
}
