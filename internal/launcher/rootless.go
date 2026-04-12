package launcher

import (
	"errors"
	"strconv"
	"strings"
)

type Request struct {
	NetNSPath string
	Binary    string
	Args      []string
	UID       int
	GID       int
}

func Command(req Request) (string, []string, error) {
	name, args, err := baseCommand(req)
	if err != nil {
		return "", nil, err
	}
	args = append(args,
		"rootlesskit",
		"--net=host",
		"--copy-up=/etc",
		strings.TrimSpace(req.Binary),
	)
	args = append(args, req.Args...)
	return name, args, nil
}

func CommandInNetNS(req Request) (string, []string, error) {
	name, args, err := baseCommand(req)
	if err != nil {
		return "", nil, err
	}
	args = append(args, strings.TrimSpace(req.Binary))
	args = append(args, req.Args...)
	return name, args, nil
}

func HostCommand(req Request) (string, []string, error) {
	name, args, err := userCommand(req)
	if err != nil {
		return "", nil, err
	}
	args = append(args,
		"rootlesskit",
		"--net=host",
		"--copy-up=/etc",
		strings.TrimSpace(req.Binary),
	)
	args = append(args, req.Args...)
	return name, args, nil
}

func UserCommand(req Request) (string, []string, error) {
	name, args, err := userCommand(req)
	if err != nil {
		return "", nil, err
	}
	args = append(args, strings.TrimSpace(req.Binary))
	args = append(args, req.Args...)
	return name, args, nil
}

func baseCommand(req Request) (string, []string, error) {
	if strings.TrimSpace(req.NetNSPath) == "" {
		return "", nil, errors.New("network namespace path is required")
	}
	if err := validateRequest(req); err != nil {
		return "", nil, err
	}

	args := []string{
		"--net=" + strings.TrimSpace(req.NetNSPath),
		"--",
		"setpriv",
	}
	_, userArgs, err := userCommand(req)
	if err != nil {
		return "", nil, err
	}
	args = append(args, userArgs...)
	return "nsenter", args, nil
}

func userCommand(req Request) (string, []string, error) {
	if err := validateRequest(req); err != nil {
		return "", nil, err
	}
	args := []string{
		"--reuid",
		strconv.Itoa(req.UID),
		"--regid",
		strconv.Itoa(req.GID),
		"--clear-groups",
	}
	return "setpriv", args, nil
}

func validateRequest(req Request) error {
	if strings.TrimSpace(req.Binary) == "" {
		return errors.New("binary is required")
	}
	if req.UID <= 0 || req.GID <= 0 {
		return errors.New("caller uid and gid are required")
	}
	return nil
}
