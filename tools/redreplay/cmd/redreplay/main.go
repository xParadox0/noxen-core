// Command redreplay independently verifies a task's RED and GREEN commits.
//
// The recorded RED evidence file supplies the failure signature and, from
// its leading "$ command" line, the RED command. redreplay exits non-zero
// if the RED commit passes, fails differently from the evidence, or the
// GREEN commit fails.
//
//	redreplay -red <rev> [-green <rev>] -evidence evidence/T0.02/red.txt
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"chronyxlabs.com/noxen-studio/tools/redreplay"
)

func main() {
	var cfg redreplay.Config
	flag.StringVar(&cfg.Repo, "repo", ".", "repository holding the commits")
	flag.StringVar(&cfg.Red, "red", "", "RED revision (required)")
	flag.StringVar(&cfg.Green, "green", "", "GREEN revision; empty replays RED only")
	evidence := flag.String("evidence", "", "recorded RED output (required)")
	flag.StringVar(&cfg.RedCmd, "red-cmd", "", `RED command; defaults to the evidence's leading "$ " line`)
	flag.StringVar(&cfg.GreenCmd, "green-cmd", "", "GREEN command; defaults to the RED command")
	verbose := flag.Bool("v", false, "print command output")
	flag.Parse()
	if cfg.Red == "" || *evidence == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: redreplay -red REV [-green REV] -evidence FILE [flags]")
		flag.PrintDefaults()
		os.Exit(2)
	}

	recorded, err := os.ReadFile(*evidence)
	if err != nil {
		fail(err)
	}
	cfg.Want = redreplay.Signature(string(recorded))
	if cfg.RedCmd == "" {
		cfg.RedCmd = recordedCommand(string(recorded))
		if cfg.RedCmd == "" {
			fail(fmt.Errorf(`%s has no leading "$ command" line; pass -red-cmd`, *evidence))
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := redreplay.Replay(ctx, cfg)
	if *verbose || errors.Is(err, redreplay.ErrRedPassed) || errors.Is(err, redreplay.ErrSignatureMismatch) {
		printOutput("red", res.RedCommit, cfg.RedCmd, res.RedOutput)
	}
	if *verbose || errors.Is(err, redreplay.ErrGreenFailed) {
		printOutput("green", res.GreenCommit, cfg.GreenCmd, res.GreenOutput)
	}
	if err != nil {
		stop()
		fail(err)
	}

	fmt.Printf("redreplay: red %s fails as recorded: %s\n", res.RedCommit, strings.Join(res.Got, ", "))
	if res.GreenCommit != "" {
		fmt.Printf("redreplay: green %s passes\n", res.GreenCommit)
	}
	fmt.Println("redreplay: ok")
}

// recordedCommand returns the command on the first "$ " line of evidence.
func recordedCommand(evidence string) string {
	s := bufio.NewScanner(strings.NewReader(evidence))
	for s.Scan() {
		if cmd, ok := strings.CutPrefix(s.Text(), "$ "); ok {
			return strings.TrimSpace(cmd)
		}
	}
	return ""
}

func printOutput(phase, commit, cmd, output string) {
	if output == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "--- %s %s: $ %s\n%s", phase, commit, cmd, output)
	if !strings.HasSuffix(output, "\n") {
		fmt.Fprintln(os.Stderr)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "redreplay: %v\n", err)
	os.Exit(1)
}
