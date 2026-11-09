package commitcheck

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	redMsg = "test(tools): add failing tests for T0.02\n" +
		"\n" +
		"TDD-Phase: red\n" +
		"Refs: T0.02\n"
	greenMsg = "chore(tools): add TDD commit checks and RED replay\n" +
		"\n" +
		"TDD-Phase: green\n" +
		"Refs: T0.02, PRD-D8, HLD-26\n" +
		"Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n"
)

func passing() error { return nil }

func failing() error { return errors.New("--- FAIL: TestAdd") }

// mustReject asserts that err is non-nil and matches every sentinel in want.
func mustReject(t *testing.T, err error, want ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error got nil")
	}
	for _, w := range want {
		if !errors.Is(err, w) {
			t.Errorf("error %q does not match %q", err, w)
		}
	}
}

func TestCommitMsg_AcceptsValidMessages(t *testing.T) {
	for name, msg := range map[string]string{
		"red":   redMsg,
		"green": greenMsg,
		"body before trailers": "feat(api): add session endpoint\n\n" +
			"Explain why the endpoint exists.\n\n" +
			"TDD-Phase: green\nRefs: T1.03\n",
		"lower-case trailer keys": "fix(api): close leak\n\ntdd-phase: green\nrefs: T1.04\n",
		"no trailing newline":     "fix(api): close leak\n\nTDD-Phase: red\nRefs: T1.04",
		"CRLF line endings":       "fix(api): close leak\r\n\r\nTDD-Phase: red\r\nRefs: T1.04\r\n",
		"leading blank lines":     "\n\nfix(api): close leak\n\nTDD-Phase: red\nRefs: T1.04\n",
		"subject of 72 characters": strings.Repeat("x", 72) +
			"\n\nTDD-Phase: red\nRefs: T1.04\n",
		"subject of 72 multi-byte characters": strings.Repeat("é", 72) +
			"\n\nTDD-Phase: red\nRefs: T1.04\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := Check(Commit{Message: msg, RunTests: passing}); err != nil {
				t.Fatalf("Check: %v", err)
			}
		})
	}
}

func TestCommitMsg_RejectsMissingPhase(t *testing.T) {
	for name, msg := range map[string]string{
		"no trailers at all": "feat(api): add session endpoint\n",
		"only Refs":          "feat(api): add session endpoint\n\nRefs: T1.03\n",
		"phase in body, not in trailer block": "feat(api): add session endpoint\n\n" +
			"TDD-Phase: red\n\nRefs: T1.03\n",
		"phase only in the subject paragraph": "feat(api): add session endpoint\nTDD-Phase: red\nRefs: T1.03\n",
		"phase only in a comment": "feat(api): add session endpoint\n\n" +
			"Refs: T1.03\n# TDD-Phase: red\n",
	} {
		t.Run(name, func(t *testing.T) {
			mustReject(t, Check(Commit{Message: msg, RunTests: passing}), ErrMissingPhase)
		})
	}
}

func TestCommitMsg_RejectsInvalidPhase(t *testing.T) {
	for _, phase := range []string{"", "refactor", "RED", "Green", "red green", "red,green"} {
		t.Run(phase, func(t *testing.T) {
			msg := "feat(api): add session endpoint\n\nTDD-Phase: " + phase + "\nRefs: T1.03\n"
			mustReject(t, Check(Commit{Message: msg, RunTests: passing}), ErrInvalidPhase)
		})
	}
	t.Run("duplicate", func(t *testing.T) {
		msg := "feat(api): add session endpoint\n\nTDD-Phase: red\nTDD-Phase: green\nRefs: T1.03\n"
		mustReject(t, Check(Commit{Message: msg, RunTests: passing}), ErrInvalidPhase)
	})
}

func TestCommitMsg_RejectsMissingRefs(t *testing.T) {
	msg := "feat(api): add session endpoint\n\nTDD-Phase: red\n"
	mustReject(t, Check(Commit{Message: msg, RunTests: passing}), ErrMissingRefs)
}

func TestCommitMsg_RejectsInvalidRefs(t *testing.T) {
	for name, refs := range map[string]string{
		"empty":         "",
		"empty entry":   "T1.03,,PRD-D8",
		"trailing sep":  "T1.03,",
		"space in item": "T1.03, PRD D8",
		"lower case":    "t1.03",
		"punctuation":   "T1.03;PRD-D8",
	} {
		t.Run(name, func(t *testing.T) {
			msg := "feat(api): add session endpoint\n\nTDD-Phase: red\nRefs: " + refs + "\n"
			mustReject(t, Check(Commit{Message: msg, RunTests: passing}), ErrInvalidRefs)
		})
	}
}

func TestCommitMsg_RejectsBadSubject(t *testing.T) {
	t.Run("73 characters", func(t *testing.T) {
		msg := strings.Repeat("x", 73) + "\n\nTDD-Phase: red\nRefs: T1.03\n"
		mustReject(t, Check(Commit{Message: msg, RunTests: passing}), ErrSubjectTooLong)
	})
	t.Run("73 multi-byte characters", func(t *testing.T) {
		msg := strings.Repeat("é", 73) + "\n\nTDD-Phase: red\nRefs: T1.03\n"
		mustReject(t, Check(Commit{Message: msg, RunTests: passing}), ErrSubjectTooLong)
	})
	t.Run("empty message", func(t *testing.T) {
		mustReject(t, Check(Commit{Message: "\n# comment only\n", RunTests: passing}),
			ErrEmptySubject, ErrMissingPhase, ErrMissingRefs)
	})
}

func TestCommitMsg_IgnoresCommentsAndVerboseDiff(t *testing.T) {
	msg := "fix(api): close leak\n\n" +
		"TDD-Phase: red\nRefs: T1.04\n" +
		"# Please enter the commit message for your changes.\n" +
		"# ------------------------ >8 ------------------------\n" +
		"# Do not modify or remove the line above.\n" +
		"diff --git a/x b/x\n" +
		"+TDD-Phase: green\n" +
		"+Visual-Baseline-Approved: nobody\n"
	calls := 0
	err := Check(Commit{
		Message:  msg,
		Paths:    []string{"tests/e2e/home.spec.ts-snapshots/home.png"},
		RunTests: func() error { calls++; return nil },
	})
	mustReject(t, err, ErrUnapprovedSnapshot)
	if errors.Is(err, ErrInvalidPhase) {
		t.Errorf("diff text below the scissors line was read as a trailer: %v", err)
	}
	if calls != 0 {
		t.Errorf("red commit ran the tests %d time(s)", calls)
	}
}

func TestCommitMsg_GreenRejectsFailingTests(t *testing.T) {
	err := Check(Commit{Message: greenMsg, RunTests: failing})
	mustReject(t, err, ErrFailingTests)
	if !strings.Contains(err.Error(), "TestAdd") {
		t.Errorf("error %q does not carry the test failure", err)
	}
}

func TestCommitMsg_GreenRequiresTestRun(t *testing.T) {
	mustReject(t, Check(Commit{Message: greenMsg}), ErrFailingTests)
}

func TestCommitMsg_RedAllowsFailingTests(t *testing.T) {
	calls := 0
	err := Check(Commit{Message: redMsg, RunTests: func() error { calls++; return failing() }})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if calls != 0 {
		t.Errorf("red commit ran the tests %d time(s)", calls)
	}
	if err := Check(Commit{Message: redMsg}); err != nil {
		t.Fatalf("Check without a test runner: %v", err)
	}
}

func TestCommitMsg_RejectsSnapshotWithoutApproval(t *testing.T) {
	snapshots := []string{
		"tests/e2e/home.spec.ts-snapshots/home-chromium-linux.png",
		"apps/web/src/__snapshots__/Button.test.tsx.snap",
		"apps/web/src/__screenshots__/Button.test.tsx/idle.png",
	}
	for _, path := range snapshots {
		for _, phase := range []string{"red", "green"} {
			t.Run(phase+" "+path, func(t *testing.T) {
				base := "test(web): update baseline\n\nTDD-Phase: " + phase + "\nRefs: T4.01\n"
				paths := []string{"apps/web/src/Button.tsx", path}

				mustReject(t, Check(Commit{Message: base, Paths: paths, RunTests: passing}),
					ErrUnapprovedSnapshot)
				mustReject(t, Check(Commit{
					Message:  base + "Visual-Baseline-Approved:\n",
					Paths:    paths,
					RunTests: passing,
				}), ErrUnapprovedSnapshot)
				mustReject(t, Check(Commit{
					Message:  "test(web): update baseline\n\nVisual-Baseline-Approved: Ana <ana@example.com>\n\nTDD-Phase: " + phase + "\nRefs: T4.01\n",
					Paths:    paths,
					RunTests: passing,
				}), ErrUnapprovedSnapshot)

				approved := base + "Visual-Baseline-Approved: Ana <ana@example.com>\n"
				if err := Check(Commit{Message: approved, Paths: paths, RunTests: passing}); err != nil {
					t.Fatalf("approved snapshot change rejected: %v", err)
				}
			})
		}
	}
	t.Run("non-snapshot paths need no approval", func(t *testing.T) {
		paths := []string{
			"apps/web/src/Button.tsx",
			"apps/web/src/snapshots.ts",
			"docs/snapshots/readme.md",
			"tests/e2e/home.spec.ts",
		}
		if err := Check(Commit{Message: redMsg, Paths: paths, RunTests: passing}); err != nil {
			t.Fatalf("Check: %v", err)
		}
	})
}

func TestCommitMsg_ReportsEveryProblem(t *testing.T) {
	msg := strings.Repeat("x", 80) + "\n\nTDD-Phase: green\n"
	err := Check(Commit{
		Message:  msg,
		Paths:    []string{"apps/web/src/__snapshots__/a.snap"},
		RunTests: failing,
	})
	mustReject(t, err, ErrSubjectTooLong, ErrMissingRefs, ErrUnapprovedSnapshot, ErrFailingTests)
}

// TestHook_EnforcesPhaseRules installs .githooks/commit-msg into a scratch
// repository and drives it through real git commits.
func TestHook_EnforcesPhaseRules(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the hook through git")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	for _, f := range []string{
		"go.mod",
		".githooks/commit-msg",
		"tools/commitcheck/check.go",
		"tools/commitcheck/cmd/commitcheck/main.go",
	} {
		copyFile(t, filepath.Join(root, f), filepath.Join(repo, f))
	}
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = gitEnv()
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	mustGit := func(args ...string) string {
		t.Helper()
		out, err := git(args...)
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	head := func() string { return strings.TrimSpace(mustGit("rev-parse", "HEAD")) }
	commit := func(msg string) (string, error) {
		t.Helper()
		mustGit("add", "-A")
		return git("commit", "-q", "-m", msg)
	}

	mustGit("init", "-q", "-b", "main")
	mustGit("config", "core.hooksPath", ".githooks")
	write(t, filepath.Join(repo, "calc", "calc.go"), "package calc\n\nfunc Add(a, b int) int { return 0 }\n")
	mustGit("add", "-A")
	mustGit("commit", "-q", "--no-verify", "-m", "chore: base\n\nTDD-Phase: green\nRefs: T0.02\n")

	// A test that fails against the current Add.
	write(t, filepath.Join(repo, "calc", "calc_test.go"), `package calc

import "testing"

func TestAdd(t *testing.T) {
	if got := Add(2, 3); got != 5 {
		t.Fatalf("Add(2, 3) = %d, want 5", got)
	}
}
`)

	t.Run("message without phase rejected", func(t *testing.T) {
		before := head()
		out, err := commit("test(calc): add failing test\n\nRefs: T0.02\n")
		if err == nil {
			t.Fatalf("commit succeeded; want the hook to reject it\n%s", out)
		}
		if !strings.Contains(out, "TDD-Phase") {
			t.Errorf("hook output does not name TDD-Phase:\n%s", out)
		}
		if head() != before {
			t.Errorf("HEAD moved")
		}
	})

	t.Run("green commit with failing test rejected", func(t *testing.T) {
		before := head()
		out, err := commit("test(calc): add failing test\n\nTDD-Phase: green\nRefs: T0.02\n")
		if err == nil {
			t.Fatalf("commit succeeded; want the hook to reject it\n%s", out)
		}
		if !strings.Contains(out, "TestAdd") {
			t.Errorf("hook output does not name the failing test:\n%s", out)
		}
		if head() != before {
			t.Errorf("HEAD moved")
		}
	})

	t.Run("red commit with failing test accepted", func(t *testing.T) {
		if out, err := commit("test(calc): add failing test\n\nTDD-Phase: red\nRefs: T0.02\n"); err != nil {
			t.Fatalf("commit: %v\n%s", err, out)
		}
	})

	t.Run("green commit tests the index, not the work tree", func(t *testing.T) {
		before := head()
		write(t, filepath.Join(repo, "calc", "calc.go"), "package calc\n\nfunc Add(a, b int) int { return a + b }\n")
		write(t, filepath.Join(repo, "notes.txt"), "unrelated\n")
		mustGit("add", "notes.txt")
		out, err := git("commit", "-q", "-m", "docs: add notes\n\nTDD-Phase: green\nRefs: T0.02\n")
		if err == nil {
			t.Fatalf("commit succeeded although the staged tree still fails TestAdd\n%s", out)
		}
		if head() != before {
			t.Errorf("HEAD moved")
		}
	})

	t.Run("green commit with passing tests accepted", func(t *testing.T) {
		if out, err := commit("feat(calc): implement Add\n\nTDD-Phase: green\nRefs: T0.02\n"); err != nil {
			t.Fatalf("commit: %v\n%s", err, out)
		}
	})

	t.Run("unapproved snapshot rejected", func(t *testing.T) {
		before := head()
		write(t, filepath.Join(repo, "web", "home.spec.ts-snapshots", "home.png"), "png\n")
		out, err := commit("test(web): add baseline\n\nTDD-Phase: red\nRefs: T0.02\n")
		if err == nil {
			t.Fatalf("commit succeeded; want the hook to reject it\n%s", out)
		}
		if !strings.Contains(out, "Visual-Baseline-Approved") {
			t.Errorf("hook output does not name Visual-Baseline-Approved:\n%s", out)
		}
		if head() != before {
			t.Errorf("HEAD moved")
		}
		if out, err := commit("test(web): add baseline\n\nTDD-Phase: red\nRefs: T0.02\nVisual-Baseline-Approved: Ana\n"); err != nil {
			t.Fatalf("approved commit: %v\n%s", err, out)
		}
	})
}

// gitEnv isolates git from the caller's configuration and from any
// GIT_* variables set by an enclosing hook.
func gitEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			env = append(env, kv)
		}
	}
	return append(env,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
