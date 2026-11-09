// Command depscan applies the dependency vulnerability policy to the JSON
// output of govulncheck, pnpm audit and the image scanner.
//
// Usage:
//
//	depscan govulncheck [-allowlist file] [-now RFC3339] <file|->
//	depscan pnpm        [-allowlist file] [-now RFC3339] <file|->
//	depscan image       [-allowlist file] [-now RFC3339] <file|->
//
// The input is the scanner's JSON output, read from the file or from
// standard input for "-". depscan never runs a scanner; `make vuln-scan`
// does and pipes the output in. -allowlist names the exceptions file
// (default tools/depscan/allowlist.yaml, relative to the working directory).
// -now replaces the clock for the allowlist expiry and is for testing only.
//
// Success prints the warnings (govulncheck only) and one line, for example
// "OK govulncheck: 0 blocking, 2 warning(s)", and exits 0. Blocking findings
// print one "FAIL ..." line each and "FAIL <n> blocking finding(s)", and exit
// 1. Expired exceptions print first (at most 50, then "... and N more expired
// exception(s)"), then the findings (at most 50, then "... and N more"). An
// unreadable or malformed allowlist or input, an approver other than Sol, an
// object with a repeated key (also under case-folding) at any depth of the
// input, an empty input, a missing config, advisories or Results structure, a
// govulncheck stream with fewer than two progress messages, or a stream that
// ends in the middle of an object prints "depscan: <message>" to standard
// error and exits 1: the gate fails closed. Bad arguments print the usage and
// exit 2, as in the other tools.
//
// Known limit: the govulncheck stream has no end marker. A stream cut inside
// the finding phase, at a message boundary, cannot be told from a complete
// one. The completion evidence is govulncheck's own exit status: run depscan
// only after govulncheck exited 0, as `make vuln-scan` does.
//
// No input string is echoed beyond 200 bytes.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"chronyxlabs.com/noxen-studio/tools/depscan"
)

const (
	usage = "usage: depscan govulncheck|pnpm|image [-allowlist file] [-now RFC3339] <file|->\n" +
		"note: a govulncheck stream cut inside the finding phase cannot be detected here;\n" +
		"      require govulncheck to exit 0 before parsing its output (make vuln-scan does)"
	defaultAllowlist = "tools/depscan/allowlist.yaml"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, os.Stdin, stdout, stderr)
}

type options struct {
	scanner   string
	allowlist string
	now       time.Time
	input     string
}

type scanner func(io.Reader, []depscan.Entry, time.Time) (depscan.Report, error)

var scanners = map[string]scanner{
	"govulncheck": depscan.Govulncheck,
	"pnpm":        depscan.Pnpm,
	"image":       depscan.Image,
}

func runWith(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opt, ok := parse(args)
	if !ok {
		say(stderr, "%s", usage)
		return 2
	}
	data, err := os.ReadFile(opt.allowlist)
	if err != nil {
		return fail(stderr, err)
	}
	allow, err := depscan.ParseAllowlist(data)
	if err != nil {
		return fail(stderr, err)
	}
	in := stdin
	if opt.input != "-" {
		f, err := os.Open(opt.input)
		if err != nil {
			return fail(stderr, err)
		}
		defer func() { _ = f.Close() }()
		in = f
	}
	rep, err := scanners[opt.scanner](in, allow, opt.now)
	if err != nil {
		return fail(stderr, err)
	}
	lines, failed := rep.Render()
	for _, l := range lines {
		say(stdout, "%s", l)
	}
	if failed {
		return 1
	}
	return 0
}

// fail prints an error and returns the failure exit status. The message is
// clipped, so nothing from an input is echoed beyond 200 bytes.
func fail(stderr io.Writer, err error) int {
	say(stderr, "depscan: %s", depscan.Clip(err.Error()))
	return 1
}

// say prints one line. A failed write to the terminal has nowhere to be
// reported, so it is dropped.
func say(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format+"\n", args...)
}

// parse reads the subcommand, its flags and exactly one input, in any order.
func parse(args []string) (options, bool) {
	opt := options{allowlist: defaultAllowlist}
	if len(args) == 0 || scanners[args[0]] == nil {
		return opt, false
	}
	opt.scanner = args[0]
	fs := flag.NewFlagSet(opt.scanner, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opt.allowlist, "allowlist", opt.allowlist, "")
	nowFlag := fs.String("now", "", "")
	var inputs []string
	rest := args[1:]
	for {
		if err := fs.Parse(rest); err != nil {
			return opt, false
		}
		if fs.NArg() == 0 {
			break
		}
		inputs = append(inputs, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(inputs) != 1 {
		return opt, false
	}
	opt.input = inputs[0]
	opt.now = time.Now()
	if *nowFlag != "" {
		t, err := time.Parse(time.RFC3339, *nowFlag)
		if err != nil {
			return opt, false
		}
		opt.now = t
	}
	return opt, true
}
