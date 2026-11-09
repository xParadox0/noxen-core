package redreplay

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testCmd = "go test ./... -count=1"

// fixtureRepo builds the repository described in testdata/make-fixture-repo.sh.
func fixtureRepo(t *testing.T) string {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("testdata", "make-fixture-repo.sh"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "repo")
	if out, err := exec.Command("sh", script, dir).CombinedOutput(); err != nil {
		t.Fatalf("make-fixture-repo.sh: %v\n%s", err, out)
	}
	return dir
}

func git(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestReplay_DetectsRedThatPasses(t *testing.T) {
	repo := fixtureRepo(t)
	_, err := Replay(context.Background(), Config{
		Repo:   repo,
		Red:    "pass-red",
		RedCmd: testCmd,
		Want:   []string{"TestZero"},
	})
	if !errors.Is(err, ErrRedPassed) {
		t.Fatalf("want ErrRedPassed got %v", err)
	}
	if !strings.Contains(err.Error(), "red commit passes") {
		t.Errorf("error %q does not say the red commit passes", err)
	}
}

func TestReplay_AcceptsFaithfulRedAndGreen(t *testing.T) {
	repo := fixtureRepo(t)
	res, err := Replay(context.Background(), Config{
		Repo:     repo,
		Red:      "good-red",
		Green:    "good-green",
		RedCmd:   testCmd,
		GreenCmd: testCmd,
		Want:     []string{"TestAdd"},
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if want := []string{"TestAdd"}; !reflect.DeepEqual(res.Got, want) {
		t.Errorf("Got = %q, want %q", res.Got, want)
	}
	if !strings.Contains(res.RedOutput, "Add(2, 3) = 0, want 5") {
		t.Errorf("RedOutput lacks the assertion failure:\n%s", res.RedOutput)
	}
	if !strings.Contains(res.GreenOutput, "ok") {
		t.Errorf("GreenOutput lacks a passing package:\n%s", res.GreenOutput)
	}
}

func TestReplay_RedOnly(t *testing.T) {
	repo := fixtureRepo(t)
	if _, err := Replay(context.Background(), Config{
		Repo:   repo,
		Red:    "good-red",
		RedCmd: testCmd,
		Want:   []string{"TestAdd"},
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
}

func TestReplay_RejectsSignatureMismatch(t *testing.T) {
	repo := fixtureRepo(t)
	_, err := Replay(context.Background(), Config{
		Repo:   repo,
		Red:    "good-red",
		RedCmd: testCmd,
		Want:   []string{"TestAdd", "TestSub"},
	})
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("want ErrSignatureMismatch got %v", err)
	}
	if !strings.Contains(err.Error(), "TestSub") {
		t.Errorf("error %q does not name the missing failure", err)
	}
}

func TestReplay_DetectsGreenThatFails(t *testing.T) {
	repo := fixtureRepo(t)
	_, err := Replay(context.Background(), Config{
		Repo:     repo,
		Red:      "good-red",
		Green:    "bad-green",
		RedCmd:   testCmd,
		GreenCmd: testCmd,
		Want:     []string{"TestAdd"},
	})
	if !errors.Is(err, ErrGreenFailed) {
		t.Fatalf("want ErrGreenFailed got %v", err)
	}
}

func TestReplay_RequiresSignature(t *testing.T) {
	repo := fixtureRepo(t)
	_, err := Replay(context.Background(), Config{Repo: repo, Red: "good-red", RedCmd: testCmd})
	if !errors.Is(err, ErrNoSignature) {
		t.Fatalf("want ErrNoSignature got %v", err)
	}
}

func TestReplay_UnknownCommit(t *testing.T) {
	repo := fixtureRepo(t)
	_, err := Replay(context.Background(), Config{
		Repo:   repo,
		Red:    "no-such-tag",
		RedCmd: testCmd,
		Want:   []string{"TestAdd"},
	})
	if err == nil {
		t.Fatalf("want error got nil")
	}
}

func TestReplay_LeavesRepositoryUntouched(t *testing.T) {
	repo := fixtureRepo(t)
	before := git(t, repo, "status", "--porcelain", "--branch")
	head := git(t, repo, "rev-parse", "HEAD")
	if _, err := Replay(context.Background(), Config{
		Repo:     repo,
		Red:      "good-red",
		Green:    "good-green",
		RedCmd:   "touch scratch-marker; " + testCmd,
		GreenCmd: "touch scratch-marker; " + testCmd,
		Want:     []string{"TestAdd"},
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got := git(t, repo, "worktree", "list", "--porcelain"); strings.Count(got, "worktree ") != 1 {
		t.Errorf("scratch worktree left behind:\n%s", got)
	}
	if got := git(t, repo, "status", "--porcelain", "--branch"); got != before {
		t.Errorf("status changed from %q to %q", before, got)
	}
	if got := git(t, repo, "rev-parse", "HEAD"); got != head {
		t.Errorf("HEAD changed from %s to %s", head, got)
	}
	if _, err := os.Stat(filepath.Join(repo, "scratch-marker")); err == nil {
		t.Errorf("RED command ran in the repository instead of a scratch worktree")
	}
}

func TestSignature(t *testing.T) {
	out := `=== RUN   TestA
--- FAIL: TestA (0.00s)
=== RUN   TestB
=== RUN   TestB/sub_case
    --- FAIL: TestB/sub_case (0.00s)
--- FAIL: TestB (0.00s)
--- PASS: TestC (0.00s)
--- FAIL: TestA (0.00s)
FAIL
FAIL	example.com/x	0.01s
# example.com/y
y/y_test.go:3:2: undefined: Nope
FAIL	example.com/y [build failed]
FAIL	example.com/z [setup failed]
FAIL
`
	want := []string{
		"TestA",
		"TestB",
		"TestB/sub_case",
		"example.com/y [build failed]",
		"example.com/z [setup failed]",
	}
	if got := Signature(out); !reflect.DeepEqual(got, want) {
		t.Errorf("Signature = %q, want %q", got, want)
	}
	if got := Signature("ok  \texample.com/x\t0.01s\n"); len(got) != 0 {
		t.Errorf("Signature of passing output = %q, want none", got)
	}
}

// TestCommand_ExitStatus drives the redreplay binary the way a verifier would.
func TestCommand_ExitStatus(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "redreplay")
	if out, err := exec.Command("go", "build", "-o", bin, "./cmd/redreplay").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	repo := fixtureRepo(t)
	evidence := filepath.Join(t.TempDir(), "red.txt")
	recorded := "$ " + testCmd + "\n" +
		"--- FAIL: TestAdd (0.00s)\n" +
		"    calc_test.go:7: Add(2, 3) = 0, want 5\n" +
		"FAIL\nFAIL\texample.com/fixture\t0.002s\nFAIL\n"
	if err := os.WriteFile(evidence, []byte(recorded), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command(bin, append([]string{"-repo", repo, "-evidence", evidence}, args...)...).CombinedOutput()
		return string(out), err
	}

	t.Run("red commit passes", func(t *testing.T) {
		out, err := run("-red", "pass-red")
		if err == nil {
			t.Fatalf("exit 0; want nonzero\n%s", out)
		}
		if !strings.Contains(out, "red commit passes") {
			t.Errorf("output does not say the red commit passes:\n%s", out)
		}
	})
	t.Run("green commit fails", func(t *testing.T) {
		out, err := run("-red", "good-red", "-green", "bad-green")
		if err == nil {
			t.Fatalf("exit 0; want nonzero\n%s", out)
		}
		if !strings.Contains(out, "green commit fails") {
			t.Errorf("output does not say the green commit fails:\n%s", out)
		}
	})
	t.Run("faithful replay", func(t *testing.T) {
		if out, err := run("-red", "good-red", "-green", "good-green"); err != nil {
			t.Fatalf("redreplay: %v\n%s", err, out)
		}
	})
	t.Run("usage error", func(t *testing.T) {
		if out, err := exec.Command(bin).CombinedOutput(); err == nil {
			t.Fatalf("exit 0 without -red; want nonzero\n%s", out)
		}
	})
}
