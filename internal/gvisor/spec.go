package gvisor

import (
	"fmt"
	"strings"
	"unicode"

	"gvisor-net/internal/config"
)

type Spec struct {
	OCIVersion string      `json:"ociVersion"`
	Process    ProcessSpec `json:"process"`
	Root       RootSpec    `json:"root"`
	Hostname   string      `json:"hostname,omitempty"`
}

type ProcessSpec struct {
	Args []string `json:"args"`
	Cwd  string   `json:"cwd"`
	Env  []string `json:"env,omitempty"`
}

type RootSpec struct {
	Path string `json:"path"`
}

func BuildSpec(cfg config.Config, workdir, payload string) (Spec, error) {
	shellParts, err := splitShellWords(cfg.Sandbox.CommandShell)
	if err != nil {
		return Spec{}, fmt.Errorf("parse sandbox command shell: %w", err)
	}
	if len(shellParts) == 0 {
		return Spec{}, fmt.Errorf("sandbox command shell is required")
	}

	cwd := strings.TrimSpace(workdir)
	if cwd == "" {
		cwd = strings.TrimSpace(cfg.Sandbox.Workdir)
	}
	if cwd == "" {
		cwd = "/"
	}

	args := make([]string, 0, 2+len(shellParts))
	args = append(args, "/box-initshim")
	args = append(args, shellParts...)
	args = append(args, payload)

	return Spec{
		OCIVersion: "1.0.2",
		Process: ProcessSpec{
			Args: args,
			Cwd:  cwd,
			Env:  append([]string(nil), cfg.Sandbox.Env...),
		},
		Root: RootSpec{
			Path: "rootfs",
		},
		Hostname: cfg.Sandbox.Hostname,
	}, nil
}

func splitShellWords(input string) ([]string, error) {
	var (
		out          []string
		token        []rune
		quote        rune
		escaped      bool
		tokenStarted bool
	)

	flush := func() {
		if !tokenStarted {
			return
		}
		out = append(out, string(token))
		token = token[:0]
		tokenStarted = false
	}

	for _, r := range input {
		if escaped {
			token = append(token, r)
			tokenStarted = true
			escaped = false
			continue
		}

		if r == '\\' {
			escaped = true
			tokenStarted = true
			continue
		}

		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			token = append(token, r)
			tokenStarted = true
			continue
		}

		if unicode.IsSpace(r) {
			flush()
			continue
		}

		if r == '\'' || r == '"' {
			quote = r
			tokenStarted = true
			continue
		}

		token = append(token, r)
		tokenStarted = true
	}

	if escaped {
		return nil, fmt.Errorf("unterminated escape")
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted token")
	}
	flush()

	return out, nil
}
