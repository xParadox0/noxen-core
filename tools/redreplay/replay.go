// Package redreplay replays a task's RED and GREEN commits for independent
// verification.
//
// The RED command must fail at the RED commit with the recorded failure
// signature, and the GREEN command must pass at the GREEN commit. Both run
// in a scratch worktree, so the caller's checkout is never touched.
package redreplay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Replay outcomes that fail verification.
var (
	ErrRedPassed         = errors.New("red commit passes")
	ErrSignatureMismatch = errors.New("red failure signature does not match the recorded one")
	ErrGreenFailed       = errors.New("green commit fails")
	ErrNoSignature       = errors.New("no recorded failure signature")
)

// Config selects the commits and commands to replay.
type Config struct {
	// Repo is the repository holding the commits; "" means ".".
	Repo string
	// Red is the RED revision. Green is the GREEN revision, or "" to replay
	// RED only.
	Red, Green string
	// RedCmd and GreenCmd are run with sh -c at the worktree root.
	// GreenCmd defaults to RedCmd.
	RedCmd, GreenCmd string
	// Want is the recorded failure signature (see Signature).
	Want []string
}

// Result is what the replay observed.
type Result struct {
	RedCommit, GreenCommit string
	RedOutput, GreenOutput string
	// Got is the failure signature of RedOutput.
	Got []string
}

var (
	failedTest = regexp.MustCompile(`(?m)^\s*--- FAIL: (\S+)`)
	failedPkg  = regexp.MustCompile(`(?m)^FAIL\s+(\S+)\s+\[(build failed|setup failed)\]`)
)

// Signature extracts the failure signature from go test output: the sorted
// names of failed tests and subtests, plus "<package> [build failed]" or
// "<package> [setup failed]" for packages that did not get as far as
// running.
func Signature(output string) []string {
	var sig []string
	for _, m := range failedTest.FindAllStringSubmatch(output, -1) {
		sig = append(sig, m[1])
	}
	for _, m := range failedPkg.FindAllStringSubmatch(output, -1) {
		sig = append(sig, m[1]+" ["+m[2]+"]")
	}
	slices.Sort(sig)
	return slices.Compact(sig)
}

// Replay checks out cfg.Red in a scratch worktree and runs cfg.RedCmd, which
// must fail with signature cfg.Want. If cfg.Green is set it then checks out
// cfg.Green in the same worktree and runs cfg.GreenCmd, which must pass.
// The worktree is removed before Replay returns.
func Replay(ctx context.Context, cfg Config) (res Result, err error) {
	want := slices.Compact(slices.Sorted(slices.Values(cfg.Want)))
	if len(want) == 0 {
		return res, ErrNoSignature
	}
	if cfg.RedCmd == "" {
		return res, errors.New("no RED command")
	}
	if cfg.GreenCmd == "" {
		cfg.GreenCmd = cfg.RedCmd
	}
	repo := cfg.Repo
	if repo == "" {
		repo = "."
	}

	if res.RedCommit, err = resolve(ctx, repo, cfg.Red); err != nil {
		return res, err
	}
	if cfg.Green != "" {
		if res.GreenCommit, err = resolve(ctx, repo, cfg.Green); err != nil {
			return res, err
		}
	}

	tmp, err := os.MkdirTemp("", "redreplay-")
	if err != nil {
		return res, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(tmp)) }()
	wt := filepath.Join(tmp, "worktree")
	if _, err := runGit(ctx, repo, "worktree", "add", "--quiet", "--detach", wt, res.RedCommit); err != nil {
		return res, err
	}
	defer func() {
		// Cleanup must run even if ctx was cancelled.
		_, rmErr := runGit(context.Background(), repo, "worktree", "remove", "--force", wt)
		err = errors.Join(err, rmErr)
	}()

	var passed bool
	if res.RedOutput, passed, err = run(ctx, wt, cfg.RedCmd); err != nil {
		return res, err
	}
	if passed {
		return res, fmt.Errorf("%w: %s", ErrRedPassed, res.RedCommit)
	}
	res.Got = Signature(res.RedOutput)
	if !slices.Equal(res.Got, want) {
		return res, fmt.Errorf("%w: missing %q, unexpected %q",
			ErrSignatureMismatch, subtract(want, res.Got), subtract(res.Got, want))
	}

	if res.GreenCommit == "" {
		return res, nil
	}
	if _, err := runGit(ctx, wt, "checkout", "--quiet", "--force", "--detach", res.GreenCommit); err != nil {
		return res, err
	}
	if _, err := runGit(ctx, wt, "clean", "--quiet", "-ffdx"); err != nil {
		return res, err
	}
	if res.GreenOutput, passed, err = run(ctx, wt, cfg.GreenCmd); err != nil {
		return res, err
	}
	if !passed {
		return res, fmt.Errorf("%w: %s", ErrGreenFailed, res.GreenCommit)
	}
	return res, nil
}

func resolve(ctx context.Context, repo, rev string) (string, error) {
	if rev == "" {
		return "", errors.New("no RED revision")
	}
	out, err := runGit(ctx, repo, "rev-parse", "--verify", "--end-of-options", rev+"^{commit}")
	return strings.TrimSpace(out), err
}

// run runs command with sh at dir and reports whether it exited 0. err is
// set only if the command could not be run at all.
func run(ctx context.Context, dir, command string) (output string, passed bool, err error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command) //nolint:gosec // G204: running the verifier's command is the point
	cmd.Dir = dir
	cmd.Env = withoutGitEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), false, ctx.Err()
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(out), false, nil
	}
	return string(out), err == nil, err
}

// runGit runs git at dir with hooks disabled, so that creating the scratch
// worktree cannot trigger the repository's checkout hooks.
func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir, "-c", "core.hooksPath=/dev/null"}, args...)...) //nolint:gosec // G204: fixed binary, caller-built arguments
	cmd.Env = withoutGitEnv(os.Environ())
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return string(out), nil
}

// withoutGitEnv drops GIT_* variables, such as GIT_DIR or GIT_INDEX_FILE
// inherited from a hook, which would redirect git away from dir.
func withoutGitEnv(env []string) []string {
	var clean []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "GIT_") {
			clean = append(clean, kv)
		}
	}
	return clean
}

// subtract returns the elements of a that are not in b.
func subtract(a, b []string) []string {
	var d []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			d = append(d, s)
		}
	}
	return d
}
