// Command commitcheck is the commit-msg hook behind .githooks/commit-msg.
//
// It checks the message file against the TDD commit rules, using the staged
// paths for the snapshot rule. For a green commit it checks the staged tree
// out into a scratch directory and runs the test command there, so unstaged
// work cannot hide a failing test. Merge commits are not checked.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"chronyxlabs.com/noxen-studio/tools/commitcheck"
)

func main() {
	testCmd := flag.String("test-cmd", "go test ./...", "shell command that must pass against the staged tree of a green commit")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: commitcheck [-test-cmd cmd] COMMIT_MSG_FILE")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if err := run(flag.Arg(0), *testCmd); err != nil {
		fmt.Fprintf(os.Stderr, "commitcheck: commit rejected:\n%s\n", err)
		os.Exit(1)
	}
}

func run(msgFile, testCmd string) error {
	msg, err := os.ReadFile(msgFile)
	if err != nil {
		return err
	}
	if _, err := git("rev-parse", "-q", "--verify", "MERGE_HEAD"); err == nil {
		return nil
	}
	staged, err := git("diff", "--cached", "--name-only", "--no-renames", "-z")
	if err != nil {
		return err
	}
	var paths []string
	for _, p := range strings.Split(staged, "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return commitcheck.Check(commitcheck.Commit{
		Message:  string(msg),
		Paths:    paths,
		RunTests: func() error { return testStaged(testCmd) },
	})
}

// testStaged runs testCmd in a checkout of the index. git points hooks at
// the index being committed through GIT_INDEX_FILE, which checkout-index
// honours.
func testStaged(testCmd string) error {
	dir, err := os.MkdirTemp("", "commitcheck-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }() // a leftover temp dir must not block the commit
	if _, err := git("checkout-index", "--all", "--prefix="+dir+string(os.PathSeparator)); err != nil {
		return err
	}

	cmd := exec.Command("sh", "-c", testCmd) //nolint:gosec // G204: running the configured test command is the point
	cmd.Dir = dir
	cmd.Env = withoutGitEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", testCmd, err, out)
	}
	return nil
}

func git(args ...string) (string, error) {
	var stderr bytes.Buffer
	cmd := exec.Command("git", args...) //nolint:gosec // G204: fixed binary, caller-built arguments
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return string(out), nil
}

// withoutGitEnv drops the GIT_* variables git sets for hooks, so that tests
// which run git of their own do not act on the repository being committed.
func withoutGitEnv(env []string) []string {
	var clean []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "GIT_") {
			clean = append(clean, kv)
		}
	}
	return clean
}
