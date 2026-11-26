// Package cli implements the chimera command line per DESIGN.md §1: a single
// command table drives parsing and --help; stdout carries data only; errors are
// one lowercase line on stderr (and a chimera.error/v1 object on stdout with
// --json); exit codes are 0 ok, 1 error, 2 usage, 3 pending.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/misty-step/chimera/pkg/config"
)

// Exit codes. No others are ever returned.
const (
	ExitOK      = 0
	ExitError   = 1
	ExitUsage   = 2
	ExitPending = 3
)

// Invocation is one run of the CLI. Tests construct it directly.
type Invocation struct {
	Args   []string
	Env    config.Env
	Dir    string // working directory; "" means the process cwd
	Stdout io.Writer
	Stderr io.Writer
}

// OSEnv reads the process environment.
func OSEnv() config.Env { return os.Getenv }

// Main runs the CLI for the process. A SIGINT or SIGTERM cancels the running
// command; after cleanup the exit code is 1.
func Main(args []string, env config.Env, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := Run(ctx, Invocation{Args: args, Env: env, Stdout: stdout, Stderr: stderr})
	if ctx.Err() != nil {
		return ExitError
	}
	return code
}

type flagSpec struct {
	Long  string
	Short byte   // 0 when none; only -K, -h, -q exist
	Arg   string // value placeholder; "" for boolean flags
	Help  string
}

type command struct {
	Path    []string
	Args    string // positional synopsis
	MinArgs int
	MaxArgs int // -1 means variadic (see lint tenant-leak)
	Summary string
	Detail  []string
	Flags   []flagSpec
	Run     func(*ctx) error
}

func (c *command) name() string { return strings.Join(c.Path, " ") }

var (
	flagJSON   = flagSpec{Long: "json", Help: "emit one JSON object on stdout"}
	flagConfig = flagSpec{Long: "config", Arg: "path", Help: "config file (default ./chimera.yaml, then $XDG_CONFIG_HOME/chimera/chimera.yaml)"}
	flagQuiet  = flagSpec{Long: "quiet", Short: 'q', Help: "suppress everything but data and errors"}
	flagHelp   = flagSpec{Long: "help", Short: 'h', Help: "show help"}
	globals    = []flagSpec{flagConfig, flagQuiet, flagHelp}
)

// commands is the single table that defines every command and its --help.
var commands = []*command{
	{
		Path: []string{"lint", "tenant-leak"}, Args: "[paths…]", MaxArgs: -1,
		Summary: "scan for secrets and tenant values",
		Detail: []string{
			"Scans tracked files (git ls-files), or the given paths, against the built-in",
			"secret rules, every tenant value in the loaded config, and the denylist file.",
			"Terms match case-insensitively at word boundaries; binary files are scanned.",
			"Prints path:line:col rule-id per finding, never the matched value.",
			"Exits 1 on any finding, on an unreadable file, or an unreadable denylist.",
		},
		Flags: []flagSpec{flagJSON},
		Run:   runLintTenantLeak,
	},
	{
		Path: []string{"ring0", "lock"}, Summary: "hash Ring-0 files into .chimera/ring0.lock",
		Detail: []string{
			"Hashes every file matching ring0.paths (SHA-256) into .chimera/ring0.lock.",
			"Changing the lock requires explicit owner approval (PRODUCT.md, Ring-0).",
		},
		Run: runRing0Lock,
	},
	{
		Path: []string{"ring0", "verify"}, Summary: "exit 1 if any Ring-0 file differs from the lock",
		Detail: []string{
			"Compares Ring-0 files against .chimera/ring0.lock: modified, added, and",
			"missing files, and ring0.paths globs that differ from the locked set.",
		},
		Flags: []flagSpec{flagJSON},
		Run:   runRing0Verify,
	},
	{
		Path: []string{"version"}, Summary: "print module version and VCS revision",
		Flags: []flagSpec{flagJSON},
		Run:   runVersion,
	},
}

// ctx is the per-invocation state handed to a command.
type ctx struct {
	context.Context
	cmd    *command
	inv    Invocation
	args   []string
	flags  map[string]string // long name → value ("true" for booleans)
	json   bool
	quiet  bool
	colorE bool // ANSI allowed on stderr
}

// cliError is a failure with an exit code, rendered per DESIGN.md §1.5.
type cliError struct {
	code     int
	object   string // what failed, e.g. a path; may be empty
	msg      string // lowercase description
	next     string // consequence or next action
	findings any
}

func (e *cliError) Error() string { return e.msg }

func usageErr(object, msg, next string) *cliError {
	return &cliError{code: ExitUsage, object: object, msg: msg, next: next}
}

// Run executes one invocation and returns its exit code.
func Run(parent context.Context, inv Invocation) int {
	if inv.Env == nil {
		inv.Env = func(string) string { return "" }
	}
	if inv.Dir == "" {
		inv.Dir, _ = os.Getwd()
	}
	jsonWanted := false
	for _, a := range inv.Args {
		if a == "--json" {
			jsonWanted = true
		}
	}
	c := &ctx{Context: parent, inv: inv, json: jsonWanted, colorE: colorAllowed(inv.Stderr, inv.Env)}

	cmd, rest, groupPath, err := resolve(inv.Args)
	if err != nil {
		return c.fail("", err)
	}
	if cmd == nil {
		// Bare `chimera`, `chimera --help`, or a noun without a verb.
		wantHelp := containsHelp(rest)
		text := helpTop()
		if len(groupPath) > 0 {
			text = helpGroup(groupPath)
		}
		if wantHelp {
			io.WriteString(inv.Stdout, text)
			return ExitOK
		}
		io.WriteString(inv.Stderr, text)
		return ExitUsage
	}
	c.cmd = cmd
	if err := c.parse(rest); err != nil {
		return c.fail(cmd.name(), err)
	}
	if c.flags["help"] == "true" {
		io.WriteString(inv.Stdout, helpCommand(cmd))
		return ExitOK
	}
	if err := cmd.Run(c); err != nil {
		return c.fail(cmd.name(), err)
	}
	return ExitOK
}

func containsHelp(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// resolve finds the longest command path that prefixes the leading
// non-flag arguments.
func resolve(args []string) (cmd *command, rest []string, group []string, err error) {
	var words []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || len(words) == 2 {
			break
		}
		words = append(words, a)
	}
	for _, c := range commands {
		if len(c.Path) <= len(words) && equal(c.Path, words[:len(c.Path)]) {
			if cmd == nil || len(c.Path) > len(cmd.Path) {
				cmd = c
			}
		}
	}
	if cmd != nil {
		return cmd, args[len(cmd.Path):], nil, nil
	}
	if len(words) == 0 {
		return nil, args, nil, nil
	}
	if isNoun(words[0]) {
		if len(words) == 1 {
			return nil, args[1:], words[:1], nil
		}
		return nil, nil, nil, usageErr(words[0], fmt.Sprintf("unknown verb %q", words[1]), fmt.Sprintf("run 'chimera %s --help'", words[0]))
	}
	return nil, nil, nil, usageErr(words[0], "unknown command", "run 'chimera --help'")
}

func isNoun(w string) bool {
	for _, c := range commands {
		if len(c.Path) == 2 && c.Path[0] == w {
			return true
		}
	}
	return false
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *ctx) parse(args []string) error {
	c.flags = map[string]string{}
	specs := append(append([]flagSpec{}, c.cmd.Flags...), globals...)
	byLong := map[string]flagSpec{}
	byShort := map[byte]flagSpec{}
	for _, f := range specs {
		byLong[f.Long] = f
		if f.Short != 0 {
			byShort[f.Short] = f
		}
	}
	next := "run 'chimera " + c.cmd.name() + " --help'"
	positional := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if positional || a == "-" || !strings.HasPrefix(a, "-") {
			c.args = append(c.args, a)
			continue
		}
		if a == "--" {
			positional = true
			continue
		}
		var spec flagSpec
		var value string
		hasValue := false
		switch {
		case strings.HasPrefix(a, "--"):
			name := a[2:]
			if k, v, ok := strings.Cut(name, "="); ok {
				name, value, hasValue = k, v, true
			}
			s, ok := byLong[name]
			if !ok {
				return usageErr("--"+name, "unknown flag", next)
			}
			spec = s
		case len(a) == 2:
			s, ok := byShort[a[1]]
			if !ok {
				return usageErr(a, "unknown flag", next)
			}
			spec = s
		default:
			return usageErr(a, "unknown flag; short flags do not combine", next)
		}
		if spec.Arg == "" {
			if hasValue {
				return usageErr("--"+spec.Long, "takes no value", next)
			}
			c.flags[spec.Long] = "true"
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				return usageErr("--"+spec.Long, "missing value <"+spec.Arg+">", next)
			}
			i++
			value = args[i]
		}
		c.flags[spec.Long] = value
	}
	if c.flags["help"] == "true" {
		return nil
	}
	c.json = c.flags["json"] == "true"
	c.quiet = c.flags["quiet"] == "true"
	if len(c.args) < c.cmd.MinArgs || (c.cmd.MaxArgs >= 0 && len(c.args) > c.cmd.MaxArgs) {
		return usageErr("", fmt.Sprintf("wrong number of arguments (got %d)", len(c.args)), "usage: chimera "+synopsis(c.cmd))
	}
	return nil
}

// loadConfig applies flag > env > file precedence. Load failures are usage errors.
func (c *ctx) loadConfig() (*config.Config, error) {
	file := c.flags["config"]
	if file != "" && !isAbs(file) {
		file = join(c.inv.Dir, file)
	}
	cfg, err := config.Load(config.Options{File: file, Dir: c.inv.Dir}, c.inv.Env)
	if err != nil {
		var le *config.LoadError
		if errors.As(err, &le) {
			return nil, usageErr("config", lower(le.Msg), "nothing was attempted")
		}
		return nil, usageErr("config", err.Error(), "nothing was attempted")
	}
	return cfg, nil
}

// info writes a progress or summary line to stderr unless -q.
func (c *ctx) info(format string, a ...any) {
	if c.quiet {
		return
	}
	fmt.Fprintf(c.inv.Stderr, format+"\n", a...)
}

// status renders a status word, adding accent color only when allowed.
func (c *ctx) status(word string) string {
	if c.colorE && word != "PASS" {
		return "\x1b[34m" + word + "\x1b[0m"
	}
	return word
}

func (c *ctx) emitJSON(v any) error {
	enc := json.NewEncoder(c.inv.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func (c *ctx) fail(command string, err error) int {
	var ce *cliError
	if !errors.As(err, &ce) {
		ce = &cliError{code: ExitError, msg: lower(err.Error())}
	}
	parts := []string{"chimera"}
	if command != "" {
		parts = append(parts, command)
	}
	if ce.object != "" {
		parts = append(parts, ce.object)
	}
	parts = append(parts, ce.msg)
	line := strings.Join(parts, ": ")
	if ce.next != "" {
		line += "; " + ce.next
	}
	line = strings.ReplaceAll(line, "\n", " ")
	if c.json {
		findings := ce.findings
		if findings == nil {
			findings = []any{}
		}
		_ = c.emitJSON(errorJSON{
			Schema:   "chimera.error/v1",
			Code:     ce.code,
			Command:  command,
			Message:  strings.TrimPrefix(line, "chimera: "),
			Findings: findings,
		})
	}
	fmt.Fprintln(c.inv.Stderr, line)
	return ce.code
}

// errorJSON is the chimera.error/v1 object written to stdout under --json.
type errorJSON struct {
	Schema   string `json:"schema"`
	Code     int    `json:"code"`
	Command  string `json:"command"`
	Message  string `json:"message"`
	Findings any    `json:"findings"`
}

func lower(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
