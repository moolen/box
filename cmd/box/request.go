package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/term"
)

const (
	envInitShimPath     = "BOX_INIT_SHIM_PATH"
	defaultInitShimPath = "/usr/local/libexec/box-initshim"
)

type ttyState struct {
	Stdin  bool
	Stdout bool
	Stderr bool
}

type runRequest struct {
	ConfigPath   string
	Payload      []string
	ShellCommand string
	InitShimPath string
	TTY          ttyState
}

type executor interface {
	Run(runRequest) error
}

type deps struct {
	executor        executor
	resolveInitShim func() string
	detectTTY       func() ttyState
}

func withDefaults(d deps) deps {
	if d.executor == nil {
		d.executor = runtimeExecutor{}
	}
	if d.resolveInitShim == nil {
		d.resolveInitShim = defaultResolveInitShim
	}
	if d.detectTTY == nil {
		d.detectTTY = defaultTTYDetector
	}
	return d
}

func runPayload(d deps, configPath string, payload []string) error {
	req, err := newRunRequest(d, configPath, payload)
	if err != nil {
		return err
	}
	return d.executor.Run(req)
}

func newRunRequest(d deps, configPath string, payload []string) (runRequest, error) {
	if len(payload) == 0 {
		return runRequest{}, errors.New("payload required after --")
	}

	return runRequest{
		ConfigPath:   configPath,
		Payload:      payload,
		ShellCommand: shellCommand(payload),
		InitShimPath: d.resolveInitShim(),
		TTY:          d.detectTTY(),
	}, nil
}

func shellCommand(args []string) string {
	if len(args) == 0 {
		return ""
	}
	escaped := make([]string, 0, len(args))
	for _, arg := range args {
		escaped = append(escaped, shellQuote(arg))
	}
	return strings.Join(escaped, " ")
}

var shellSafePattern = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if shellSafePattern.MatchString(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
}

func defaultResolveInitShim() string {
	return resolveInitShimPath(os.Getenv, os.Executable, fileExists)
}

func resolveInitShimPath(getenv func(string) string, executable func() (string, error), exists func(string) bool) string {
	if fromEnv := strings.TrimSpace(getenv(envInitShimPath)); fromEnv != "" {
		return fromEnv
	}
	exePath, err := executable()
	if err == nil && exePath != "" {
		sibling := filepath.Join(filepath.Dir(exePath), "box-initshim")
		if exists(sibling) {
			return sibling
		}
	}
	return defaultInitShimPath
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func defaultTTYDetector() ttyState {
	return detectTTY(os.Stdin, os.Stdout, os.Stderr, isTerminalFD)
}

func detectTTY(stdin, stdout, stderr *os.File, isTerminal func(fd uintptr) bool) ttyState {
	state := ttyState{}
	if stdin != nil {
		state.Stdin = isTerminal(stdin.Fd())
	}
	if stdout != nil {
		state.Stdout = isTerminal(stdout.Fd())
	}
	if stderr != nil {
		state.Stderr = isTerminal(stderr.Fd())
	}
	return state
}

func isTerminalFD(fd uintptr) bool {
	return term.IsTerminal(int(fd))
}
