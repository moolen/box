package rootfs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
)

var (
	requiredReadonlyBinds = []string{"/bin", "/sbin", "/usr", "/lib", "/lib64"}
	optionalReadonlyBinds = []string{"/etc/alternatives", "/etc/ca-certificates", "/etc/pki", "/etc/ssl", "/opt", "/snap", "/nix"}
	writableRuntimeDirs   = []string{"/tmp", "/var/tmp", "/run", "/var/run", "/var/cache"}
)

type PlanRequest struct {
	RootfsMode       string
	RepoPath         string
	Workdir          string
	NetworkMode      string
	GatewayIP        string
	SandboxHostn     string
	BuildKitEnabled  bool
	BuildKitHelper   string
	BuildKitStateDir string
	BuildKitRunDir   string
	DockerEnabled    bool
	DockerUser       string
	DockerUID        int
	DockerGID        int
	DockerHomeDir    string
	DockerRuntimeDir string
	DockerDataRoot   string
	DockerSocketPath string
	DockerHTTPProxy  string
	DockerHTTPSProxy string
	DockerNoProxy    string
	ExtraRO          []string
	ExtraRW          []string
}

type Bind struct {
	Source   string
	Target   string
	ReadOnly bool
}

type GeneratedFile struct {
	Path    string
	Content string
	Mode    os.FileMode
}

type Plan struct {
	Binds          []Bind
	GeneratedFiles []GeneratedFile
	WritableDirs   []string
	WritableOwners map[string]DirOwner
}

type DirOwner struct {
	UID int
	GID int
}

func BuildPlan(req PlanRequest) (Plan, error) {
	mode := strings.TrimSpace(req.RootfsMode)
	if mode == "" {
		return Plan{}, errors.New("rootfs mode is required")
	}
	if mode != "host-overlay" && mode != "image" {
		return Plan{}, fmt.Errorf("unsupported rootfs mode %q", mode)
	}

	plan := Plan{
		Binds:          make([]Bind, 0, 24),
		GeneratedFiles: generatedEtcFiles(req),
		WritableDirs:   make([]string, 0, 8),
		WritableOwners: make(map[string]DirOwner),
	}

	for _, path := range writableRuntimeDirs {
		plan.WritableDirs = appendUniquePath(plan.WritableDirs, path)
	}
	if req.BuildKitEnabled {
		if stateDir := strings.TrimSpace(req.BuildKitStateDir); stateDir != "" {
			plan.WritableDirs = appendUniquePath(plan.WritableDirs, stateDir)
		}
		if runDir := strings.TrimSpace(req.BuildKitRunDir); runDir != "" {
			plan.WritableDirs = appendUniquePath(plan.WritableDirs, runDir)
		}
	}
	if req.DockerEnabled {
		if homeDir := strings.TrimSpace(req.DockerHomeDir); homeDir != "" {
			plan.WritableDirs = appendUniquePath(plan.WritableDirs, homeDir)
			plan.WritableOwners[homeDir] = DirOwner{UID: req.DockerUID, GID: req.DockerGID}
		}
		if runtimeDir := strings.TrimSpace(req.DockerRuntimeDir); runtimeDir != "" {
			plan.WritableDirs = appendUniquePath(plan.WritableDirs, runtimeDir)
			plan.WritableOwners[runtimeDir] = DirOwner{UID: req.DockerUID, GID: req.DockerGID}
		}
		if dataRoot := strings.TrimSpace(req.DockerDataRoot); dataRoot != "" {
			plan.WritableDirs = appendUniquePath(plan.WritableDirs, dataRoot)
			plan.WritableOwners[dataRoot] = DirOwner{UID: req.DockerUID, GID: req.DockerGID}
		}
	}

	if mode != "host-overlay" {
		return plan, nil
	}

	for _, src := range requiredReadonlyBinds {
		plan.Binds = append(plan.Binds, Bind{Source: src, Target: src, ReadOnly: true})
	}
	for _, src := range optionalReadonlyBinds {
		if _, err := os.Stat(src); err == nil {
			plan.Binds = append(plan.Binds, Bind{Source: src, Target: src, ReadOnly: true})
		}
	}

	if strings.TrimSpace(req.RepoPath) != "" && strings.TrimSpace(req.Workdir) != "" {
		plan.Binds = append(plan.Binds, Bind{
			Source:   req.RepoPath,
			Target:   req.Workdir,
			ReadOnly: false,
		})
	}
	for _, src := range req.ExtraRO {
		src = strings.TrimSpace(src)
		if src == "" || slices.Contains(requiredReadonlyBinds, src) {
			continue
		}
		plan.Binds = append(plan.Binds, Bind{Source: src, Target: src, ReadOnly: true})
	}
	for _, src := range req.ExtraRW {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		plan.Binds = append(plan.Binds, Bind{Source: src, Target: src, ReadOnly: false})
	}

	return plan, nil
}

func appendUniquePath(paths []string, path string) []string {
	path = strings.TrimSpace(path)
	if path == "" || slices.Contains(paths, path) {
		return paths
	}
	return append(paths, path)
}

func generatedEtcFiles(req PlanRequest) []GeneratedFile {
	hostname := strings.TrimSpace(req.SandboxHostn)
	if hostname == "" {
		hostname = "box"
	}

	nameserver := "127.0.0.1"
	if usesGatewayDNS(req.NetworkMode) && strings.TrimSpace(req.GatewayIP) != "" {
		nameserver = strings.TrimSpace(req.GatewayIP)
	}

	passwdContent := "root:x:0:0:root:/root:/bin/sh\n"
	groupContent := "root:x:0:\n"
	if req.DockerEnabled {
		passwdContent += dockerPasswdEntry(req)
		groupContent += dockerGroupEntry(req)
	}

	files := []GeneratedFile{
		{
			Path:    "/etc/resolv.conf",
			Content: "nameserver " + nameserver + "\noptions ndots:0\n",
			Mode:    0o644,
		},
		{
			Path:    "/etc/hosts",
			Content: "127.0.0.1 localhost\n127.0.1.1 " + hostname + "\n",
			Mode:    0o644,
		},
		{
			Path:    "/etc/hostname",
			Content: hostname + "\n",
			Mode:    0o644,
		},
		{
			Path:    "/etc/passwd",
			Content: passwdContent,
			Mode:    0o644,
		},
		{
			Path:    "/etc/group",
			Content: groupContent,
			Mode:    0o644,
		},
	}

	if req.DockerEnabled {
		files = append(files, dockerIdentityFiles(req)...)
		files = append(files, dockerDaemonConfigFile(req))
		if dockerClientProxyConfigured(req) {
			files = append(files, dockerClientConfigFile(req))
		}
	}
	if req.BuildKitEnabled {
		files = append(files, buildkitDaemonlessHelperFile(req))
		files = append(files, buildkitClientWrapperFile())
	}

	return files
}

func buildkitDaemonlessHelperFile(req PlanRequest) GeneratedFile {
	path := strings.TrimSpace(req.BuildKitHelper)
	if path == "" {
		path = "/box/bin/buildctl-daemonless.sh"
	}
	runDir := strings.TrimSpace(req.BuildKitRunDir)
	if runDir == "" {
		runDir = "/run/buildkit"
	}

	content := strings.TrimSpace(fmt.Sprintf(`#!/bin/sh
set -eu

: ${BUILDCTL=buildctl}
: ${BUILDCTL_CONNECT_RETRIES_MAX=10}
: ${BUILDKITD=buildkitd}
: ${BUILDKITD_FLAGS=}
: ${BUILDKIT_RUN_DIR=%s}
: ${ROOTLESSKIT=rootlesskit}

if [ -n "${BUILDKIT_HOST:-}" ]; then
    exec buildctl --addr="$BUILDKIT_HOST" "$@"
fi

if [ -S "$BUILDKIT_RUN_DIR/buildkitd.sock" ]; then
    exec buildctl --addr="unix://$BUILDKIT_RUN_DIR/buildkitd.sock" "$@"
fi

tmp=$(mktemp -d /tmp/buildctl-daemonless.XXXXXX)
trap 'kill $(cat "$tmp/pid") 2>/dev/null || true; wait $(cat "$tmp/pid") 2>/dev/null || true; rm -rf "$tmp"' EXIT

start_buildkitd() {
    addr=
    helper=
    if [ "$(id -u)" = 0 ]; then
        addr=unix://$BUILDKIT_RUN_DIR/buildkitd.sock
    else
        addr=unix://$XDG_RUNTIME_DIR/buildkit/buildkitd.sock
        helper=$ROOTLESSKIT
    fi
    $helper $BUILDKITD $BUILDKITD_FLAGS --addr=$addr >"$tmp/log" 2>&1 &
    pid=$!
    echo "$pid" >"$tmp/pid"
    echo "$addr" >"$tmp/addr"
}

wait_for_buildkitd() {
    addr=$(cat "$tmp/addr")
    try=0
    max=$BUILDCTL_CONNECT_RETRIES_MAX
    until $BUILDCTL --addr=$addr debug workers >/dev/null 2>&1; do
        if [ "$try" -gt "$max" ]; then
            echo >&2 "could not connect to $addr after $max trials"
            echo >&2 "========== log =========="
            cat >&2 "$tmp/log"
            exit 1
        fi
        sleep "$(awk "BEGIN{print (100 + $try * 20) * 0.001}")"
        try=$(expr "$try" + 1)
    done
}

start_buildkitd
wait_for_buildkitd
exec $BUILDCTL --addr="$(cat "$tmp/addr")" "$@"
`, runDir)) + "\n"

	return GeneratedFile{
		Path:    path,
		Content: content,
		Mode:    0o755,
	}
}

func buildkitClientWrapperFile() GeneratedFile {
	return GeneratedFile{
		Path: "/box/bin/buildctl",
		Content: strings.TrimSpace(`#!/bin/sh
set -eu

has_arg() {
    want=$1
    shift
    for arg in "$@"; do
        if [ "$arg" = "$want" ]; then
            return 0
        fi
    done
    return 1
}

has_build_arg_opt() {
    want=$1
    shift
    expect_value=0
    for arg in "$@"; do
        if [ "$expect_value" = 1 ]; then
            case "$arg" in
                build-arg:${want}=*)
                    return 0
                    ;;
            esac
            expect_value=0
            continue
        fi
        case "$arg" in
            --opt)
                expect_value=1
                ;;
            --opt=build-arg:${want}=*)
                return 0
                ;;
        esac
    done
    return 1
}

inject_build_proxy_args() {
    if ! has_arg build "$@"; then
        return 0
    fi
    if [ -n "${BOX_BUILDKIT_HTTP_PROXY:-}" ] && ! has_build_arg_opt HTTP_PROXY "$@"; then
        set -- "$@" --opt "build-arg:HTTP_PROXY=$BOX_BUILDKIT_HTTP_PROXY"
    fi
    if [ -n "${BOX_BUILDKIT_HTTPS_PROXY:-}" ] && ! has_build_arg_opt HTTPS_PROXY "$@"; then
        set -- "$@" --opt "build-arg:HTTPS_PROXY=$BOX_BUILDKIT_HTTPS_PROXY"
    fi
    if [ -n "${BOX_BUILDKIT_NO_PROXY:-}" ] && ! has_build_arg_opt NO_PROXY "$@"; then
        set -- "$@" --opt "build-arg:NO_PROXY=$BOX_BUILDKIT_NO_PROXY"
    fi
    exec /usr/bin/buildctl "$@"
}

if [ "$#" -gt 0 ]; then
    case "$1" in
        --addr|--addr=*)
            exec /usr/bin/buildctl "$@"
            ;;
    esac
fi

if [ -n "${BUILDKIT_HOST:-}" ]; then
    if [ -n "${BOX_BUILDKIT_HOME:-}" ]; then
        mkdir -p "$BOX_BUILDKIT_HOME"
        export HOME="$BOX_BUILDKIT_HOME"
    fi
    set -- --addr="$BUILDKIT_HOST" "$@"
    inject_build_proxy_args "$@"
fi

exec /usr/bin/buildctl "$@"
`) + "\n",
		Mode: 0o755,
	}
}

func dockerPasswdEntry(req PlanRequest) string {
	user := strings.TrimSpace(req.DockerUser)
	homeDir := strings.TrimSpace(req.DockerHomeDir)
	if user == "" || homeDir == "" {
		return ""
	}
	return fmt.Sprintf("%s:x:%d:%d:%s:%s:/bin/sh\n", user, req.DockerUID, req.DockerGID, user, homeDir)
}

func dockerGroupEntry(req PlanRequest) string {
	user := strings.TrimSpace(req.DockerUser)
	if user == "" {
		return ""
	}
	return fmt.Sprintf("%s:x:%d:\n", user, req.DockerGID)
}

func dockerIdentityFiles(req PlanRequest) []GeneratedFile {
	user := strings.TrimSpace(req.DockerUser)
	if user == "" {
		return nil
	}

	return []GeneratedFile{
		{
			Path:    "/etc/subuid",
			Content: user + ":100000:65536\n",
			Mode:    0o644,
		},
		{
			Path:    "/etc/subgid",
			Content: user + ":100000:65536\n",
			Mode:    0o644,
		},
	}
}

func usesGatewayDNS(mode string) bool {
	mode = strings.TrimSpace(mode)
	return strings.EqualFold(mode, "monitor") || strings.EqualFold(mode, "enforce")
}

func dockerDaemonConfigFile(req PlanRequest) GeneratedFile {
	socketPath := strings.TrimSpace(req.DockerSocketPath)
	if socketPath == "" {
		socketPath = "/run/user/1000/docker.sock"
	}

	config := map[string]any{
		"bridge":         "none",
		"features":       map[string]bool{"containerd-snapshotter": false},
		"hosts":          []string{"unix://" + socketPath},
		"ip-forward":     false,
		"ip6tables":      false,
		"ip-masq":        false,
		"iptables":       false,
		"storage-driver": "vfs",
		"proxies": map[string]string{
			"http-proxy":  strings.TrimSpace(req.DockerHTTPProxy),
			"https-proxy": strings.TrimSpace(req.DockerHTTPSProxy),
			"no-proxy":    strings.TrimSpace(req.DockerNoProxy),
		},
	}
	if dataRoot := strings.TrimSpace(req.DockerDataRoot); dataRoot != "" {
		config["data-root"] = dataRoot
	}

	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("marshal docker daemon config: %v", err))
	}
	content = append(content, '\n')
	return GeneratedFile{
		Path:    "/etc/docker/daemon.json",
		Content: string(content),
		Mode:    0o644,
	}
}

func dockerClientProxyConfigured(req PlanRequest) bool {
	return strings.TrimSpace(req.DockerHTTPProxy) != "" ||
		strings.TrimSpace(req.DockerHTTPSProxy) != "" ||
		strings.TrimSpace(req.DockerNoProxy) != ""
}

func dockerClientConfigFile(req PlanRequest) GeneratedFile {
	config := map[string]any{
		"proxies": map[string]any{
			"default": map[string]string{
				"httpProxy":  strings.TrimSpace(req.DockerHTTPProxy),
				"httpsProxy": strings.TrimSpace(req.DockerHTTPSProxy),
				"noProxy":    strings.TrimSpace(req.DockerNoProxy),
			},
		},
	}

	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("marshal docker client config: %v", err))
	}
	content = append(content, '\n')
	return GeneratedFile{
		Path:    "/etc/docker/config.json",
		Content: string(content),
		Mode:    0o644,
	}
}
