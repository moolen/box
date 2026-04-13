package integration

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gvisor-net/integration/testenv"
	"gvisor-net/internal/config"
	"gvisor-net/internal/rootfs"
)

func TestBoxRunsPwd(t *testing.T) {
	output := runBoxSmoke(t, "/bin/pwd")
	if strings.TrimSpace(output) == "" {
		t.Fatal("pwd output is empty")
	}
}

func TestBoxRunsEnv(t *testing.T) {
	output := runBoxSmoke(t, "/usr/bin/env")
	if !strings.Contains(output, "PATH=") {
		t.Fatalf("env output = %q, want PATH entry", output)
	}
	if !strings.Contains(output, "HTTP_PROXY=http://") {
		t.Fatalf("env output = %q, want HTTP_PROXY host intercept env", output)
	}
	if !strings.Contains(output, "HTTPS_PROXY=http://") {
		t.Fatalf("env output = %q, want HTTPS_PROXY host intercept env", output)
	}
	if !strings.Contains(output, "WS_PROXY=http://") {
		t.Fatalf("env output = %q, want WS_PROXY host intercept env", output)
	}
	if !strings.Contains(output, "WSS_PROXY=http://") {
		t.Fatalf("env output = %q, want WSS_PROXY host intercept env", output)
	}
	if !strings.Contains(output, "SSL_CERT_FILE="+rootfs.TrustedCABundlePath) {
		t.Fatalf("env output = %q, want runtime CA env injection", output)
	}
}

func TestBoxResolvesExampleDotComWithGetent(t *testing.T) {
	output := runBoxSmoke(t, "bash", "-lc", "getent hosts example.com")
	if !strings.Contains(strings.ToLower(output), "example.com") {
		t.Fatalf("getent output = %q, want example.com hostname", output)
	}
}

func TestBoxCanCurlExampleDotCom(t *testing.T) {
	output := runBoxSmoke(t, "curl", "http://example.com")
	if !strings.Contains(output, "Example Domain") {
		t.Fatalf("curl output = %q, want Example Domain response body", output)
	}
}

func TestBoxCanCurlExampleDotComWithoutProxyEnv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, []string{"example.com"}, nil)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
		"curl", "-sS", "http://example.com",
	)
	if err != nil {
		t.Fatalf("run box transparent http curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("transparent http curl output = %q, want Example Domain response body", stdout)
	}
}

func TestBoxCanCurlHTTPSExampleDotCom(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, []string{"example.com"}, nil)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "curl", "-sS", "https://example.com")
	if err != nil {
		t.Fatalf("run box https curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("https curl output = %q, want Example Domain response body", stdout)
	}
}

func TestBoxCanCurlHTTPSExampleDotComWithoutProxyEnv(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, []string{"example.com"}, nil)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
		"curl", "-sS", "https://example.com",
	)
	if err != nil {
		t.Fatalf("run box transparent https curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("transparent https curl output = %q, want Example Domain response body", stdout)
	}
}

func TestBoxAllowsProxiedWebSocketHandshake(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	port := startLocalWebSocketHandshakeServer(t)
	binary := testenv.BuildBoxBinary(t)
	gatewayIP := gatewayIPForTest(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{{
		CIDR:  gatewayIP + "/32",
		Ports: []int{port},
	}})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"bash", "-lc", fmt.Sprintf("curl -v --max-time 5 ws://%s:%d/chat >/tmp/ws.out 2>/tmp/ws.err; cat /tmp/ws.out; echo '---STDERR---'; cat /tmp/ws.err; exit 0", gatewayIP, port),
	)
	if err != nil {
		t.Fatalf("run box proxied ws curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "101 Switching Protocols") || !strings.Contains(stdout, "Received 101, Switching to WebSocket") {
		t.Fatalf("proxied ws output missing websocket handshake success; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxAllowsTransparentWebSocketHandshake(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	port := startLocalWebSocketHandshakeServer(t)
	binary := testenv.BuildBoxBinary(t)
	gatewayIP := gatewayIPForTest(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{{
		CIDR:  gatewayIP + "/32",
		Ports: []int{port},
	}})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "WS_PROXY", "-u", "WSS_PROXY", "-u", "http_proxy", "-u", "https_proxy", "-u", "ws_proxy", "-u", "wss_proxy",
		"bash", "-lc", fmt.Sprintf("curl -v --max-time 5 ws://%s:%d/chat >/tmp/ws.out 2>/tmp/ws.err; cat /tmp/ws.out; echo '---STDERR---'; cat /tmp/ws.err; exit 0", gatewayIP, port),
	)
	if err != nil {
		t.Fatalf("run box transparent ws curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "101 Switching Protocols") || !strings.Contains(stdout, "Received 101, Switching to WebSocket") {
		t.Fatalf("transparent ws output missing websocket handshake success; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxAllowsProxiedSecureWebSocketHandshake(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{{
		Hostname: "echo.websocket.org",
		Ports:    []int{443},
		HTTP: &config.HTTPPolicyConfig{
			Path: []string{"/"},
		},
	}})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"bash", "-lc", "curl -v --max-time 5 wss://echo.websocket.org/ >/tmp/wss.out 2>/tmp/wss.err; cat /tmp/wss.out; echo '---STDERR---'; cat /tmp/wss.err; exit 0",
	)
	if err != nil {
		t.Fatalf("run box proxied wss curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Request served by") || !strings.Contains(stdout, "101 Switching Protocols") || !strings.Contains(stdout, "Received 101, Switching to WebSocket") {
		t.Fatalf("proxied wss output missing websocket handshake success; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxAllowsTransparentSecureWebSocketHandshake(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{{
		Hostname: "echo.websocket.org",
		Ports:    []int{443},
		HTTP: &config.HTTPPolicyConfig{
			Path: []string{"/"},
		},
	}})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "WS_PROXY", "-u", "WSS_PROXY", "-u", "http_proxy", "-u", "https_proxy", "-u", "ws_proxy", "-u", "wss_proxy",
		"bash", "-lc", "curl -v --max-time 5 wss://echo.websocket.org/ >/tmp/wss.out 2>/tmp/wss.err; cat /tmp/wss.out; echo '---STDERR---'; cat /tmp/wss.err; exit 0",
	)
	if err != nil {
		t.Fatalf("run box transparent wss curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Request served by") || !strings.Contains(stdout, "101 Switching Protocols") || !strings.Contains(stdout, "Received 101, Switching to WebSocket") {
		t.Fatalf("transparent wss output missing websocket handshake success; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxBlocksWebSocketHandshakeForPathMismatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	port := startLocalWebSocketHandshakeServer(t)
	binary := testenv.BuildBoxBinary(t)
	gatewayIP := gatewayIPForTest(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{{
		Hostname: "ws.local",
		Ports:    []int{port},
		HTTP: &config.HTTPPolicyConfig{
			Path: []string{"/allowed*"},
		},
	}})

	stdout, stderr, _ := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"bash", "-lc", fmt.Sprintf("curl -v --max-time 5 --resolve ws.local:%d:%s ws://ws.local:%d/blocked >/tmp/ws.out 2>/tmp/ws.err; cat /tmp/ws.out; echo '---STDERR---'; cat /tmp/ws.err; exit 0", port, gatewayIP, port),
	)
	if !strings.Contains(stdout, "403 Forbidden") || !strings.Contains(stdout, "Refused WebSocket upgrade: 403") {
		t.Fatalf("ws path mismatch output = %q, want websocket upgrade refusal; stderr=%q", stdout, stderr)
	}
}

func TestBoxBlocksSecureWebSocketHandshakeForPathMismatch(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{{
		Hostname: "echo.websocket.org",
		Ports:    []int{443},
		HTTP: &config.HTTPPolicyConfig{
			Path: []string{"/allowed*"},
		},
	}})

	stdout, stderr, _ := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"bash", "-lc", "curl -v --max-time 5 wss://echo.websocket.org/ >/tmp/wss.out 2>/tmp/wss.err; cat /tmp/wss.out; echo '---STDERR---'; cat /tmp/wss.err; exit 0",
	)
	if !strings.Contains(stdout, "403 Forbidden") || !strings.Contains(stdout, "Refused WebSocket upgrade: 403") {
		t.Fatalf("wss path mismatch output = %q, want websocket upgrade refusal; stderr=%q", stdout, stderr)
	}
}

func TestBoxTransparentHTTPSPathRuleBlocksMismatchedPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "example.com",
			Ports:    []int{443},
			HTTP: &config.HTTPPolicyConfig{
				Path: []string{"/foo*"},
			},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
		"curl", "-sS", "https://example.com/",
	)
	if strings.Contains(stdout, "Example Domain") {
		t.Fatalf("path-mismatched transparent https unexpectedly returned body; stdout=%q", stdout)
	}
	if !strings.Contains(stdout, "no_matching_rule") {
		t.Fatalf("transparent https path mismatch stdout = %q, want policy deny reason; stderr=%q err=%v", stdout, stderr, err)
	}
}

func TestBoxProxiedHTTPSPathRuleAllowsMatchingPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "example.com",
			Ports:    []int{443},
			HTTP: &config.HTTPPolicyConfig{
				Path: []string{"/"},
			},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-sS", "https://example.com/",
	)
	if err != nil {
		t.Fatalf("run box proxied https curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("proxied https curl output = %q, want Example Domain response body", stdout)
	}
}

func TestBoxProxiedHTTPSPathRuleBlocksMismatchedPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "example.com",
			Ports:    []int{443},
			HTTP: &config.HTTPPolicyConfig{
				Path: []string{"/foo*"},
			},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-sS", "https://example.com/",
	)
	if strings.Contains(stdout, "Example Domain") {
		t.Fatalf("path-mismatched proxied https unexpectedly returned body; stdout=%q", stdout)
	}
	if !strings.Contains(stdout, "no_matching_rule") {
		t.Fatalf("proxied https path mismatch stdout = %q, want policy deny reason; stderr=%q err=%v", stdout, stderr, err)
	}
}

func TestBoxProxiedHTTPSAllowsWildcardHostnameRule(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "*.github.com",
			Ports:    []int{443},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-sS", "https://api.github.com/",
	)
	if err != nil {
		t.Fatalf("run box proxied wildcard https curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, `"current_user_url"`) {
		t.Fatalf("proxied wildcard https output = %q, want GitHub API body marker", stdout)
	}
}

func TestBoxTransparentHTTPSAllowsWildcardHostnameRule(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "*.github.com",
			Ports:    []int{443},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
		"curl", "-sS", "https://api.github.com/",
	)
	if err != nil {
		t.Fatalf("run box transparent wildcard https curl error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}
	if !strings.Contains(stdout, `"current_user_url"`) {
		t.Fatalf("transparent wildcard https output = %q, want GitHub API body marker", stdout)
	}
}

func TestBoxBlocksNonHTTPTCPForAllowedCIDRRule(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "nc")

	githubIPv4 := mustLookupIPv4(t, "github.com")
	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{
		{
			CIDR:  githubIPv4 + "/32",
			Ports: []int{22},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
		"bash", "-lc", "timeout 5s nc "+githubIPv4+" 22 < /dev/null | head -n 1",
	)
	if err == nil && strings.Contains(stdout, "SSH-2.0-") {
		t.Fatalf("non-http tcp unexpectedly reached upstream service under cidr allow rule; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxBlocksNonHTTPTCPForNonMatchingPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "nc")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, []string{"example.com"}, nil)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
		"bash", "-lc", "timeout 5s nc github.com 22 < /dev/null | head -n 1",
	)
	if err == nil && strings.Contains(stdout, "SSH-2.0-") {
		t.Fatalf("non-http tcp unexpectedly reached upstream service without a matching policy; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxAllowsICMPToLiteralIPWithoutMatchingPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "ping")

	exampleIPv4 := mustLookupIPv4(t, "example.com")
	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, []string{"allowed.example"}, nil)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"ping", "-c", "1", "-W", "5", exampleIPv4,
	)
	if err != nil {
		t.Fatalf("icmp to literal ip failed despite pass-through behavior; stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if !strings.Contains(stdout, "1 received") && !strings.Contains(stdout, "1 packets received") {
		t.Fatalf("icmp output = %q, want successful echo response; stderr=%q", stdout, stderr)
	}
}

func TestBoxBlocksUDPForOtherwiseAllowedHostnameRule(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)
	testenv.RequireCommands(t, "python3")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "time.cloudflare.com",
			Ports:    []int{123},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
		"python3", "-c", `
import socket, sys
query = b"\x1b" + (47 * b"\0")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2)
sock.sendto(query, ("time.cloudflare.com", 123))
try:
    data, _ = sock.recvfrom(512)
    print("unexpected-response", len(data))
    sys.exit(0)
except TimeoutError:
    print("udp-blocked")
    sys.exit(0)
`,
	)
	if err != nil {
		t.Fatalf("udp probe command failed; stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if !strings.Contains(stdout, "udp-blocked") {
		t.Fatalf("udp to otherwise allowed hostname unexpectedly succeeded; stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestBoxShowsSandboxInterfaceAddress(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	cfg, err := config.Load("box.yaml", binary.ModuleRoot)
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	prefix, err := netip.ParsePrefix(cfg.Network.Subnet)
	if err != nil {
		t.Fatalf("ParsePrefix(%q) error = %v", cfg.Network.Subnet, err)
	}
	hostIPOutput, err := exec.Command("ip", "-4", "-o", "addr", "show").CombinedOutput()
	if err != nil {
		t.Fatalf("host ip command error = %v: %s", err, strings.TrimSpace(string(hostIPOutput)))
	}

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--", "ip", "-4", "-o", "addr", "show")
	if err != nil {
		t.Fatalf("run box ip command error = %v; stdout=%q stderr=%q", err, stdout, stderr)
	}

	sandboxCIDR := firstNonLoopbackIPv4Prefix(t, stdout)
	if sandboxCIDR.Bits() != 30 {
		t.Fatalf("sandbox interface prefix = %q, want /30 allocation from subnet pool", sandboxCIDR)
	}
	if !prefix.Contains(sandboxCIDR.Addr()) {
		t.Fatalf("sandbox interface prefix = %q, want address within configured pool %q", sandboxCIDR, prefix)
	}
	if strings.Contains(string(hostIPOutput), sandboxCIDR.String()) {
		t.Skipf("host already exposes sandbox address %q; dirty host state", sandboxCIDR)
	}
	if stdout == string(hostIPOutput) {
		t.Fatalf("sandbox ip output matched host network view exactly; stdout=%q", stdout)
	}
}

func TestBoxEnforceBlocksDisallowedTraffic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteEnforceConfig(t, []string{"allowed.example"}, nil)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--", "getent", "hosts", "example.com")
	if err == nil {
		t.Fatalf("expected enforce mode to block example.com resolution; stdout=%q stderr=%q", stdout, stderr)
	}
	if strings.Contains(stdout, "example.com") {
		t.Fatalf("blocked resolution unexpectedly returned example.com in stdout=%q", stdout)
	}
}

func TestBoxRunsOpenCodeFromMountedCustomBinDir(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	opencodePath, err := exec.LookPath("opencode")
	if err != nil {
		t.Skipf("opencode not available on host PATH: %v", err)
	}
	opencodePath, err = filepath.Abs(opencodePath)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", opencodePath, err)
	}
	hostBinDir := filepath.Dir(opencodePath)
	for _, root := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/snap", "/nix"} {
		if hostBinDir == root || strings.HasPrefix(hostBinDir, root+"/") {
			t.Skipf("opencode resolved under default host-overlay bind root %q (bin dir %q); need non-default mounted bin dir", root, hostBinDir)
		}
	}
	hostPath := os.Getenv("PATH")

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteOpenCodeMonitorConfig(t, hostBinDir, hostPath)

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"timeout", "20s",
		"opencode", "run", "hi",
		"--model", "opencode/gpt-5-nano",
		"--agent", "title",
	)
	if strings.Contains(stderr, `listen udp 100.96.0.1:53: bind: address already in use`) {
		t.Skipf("host DNS bind address already in use for monitor mode: %q", stderr)
	}

	lowerStderr := strings.ToLower(stderr)
	if strings.Contains(lowerStderr, "command not found") {
		t.Fatalf("opencode resolution failed in sandbox; stderr=%q", stderr)
	}
	if err != nil && !strings.Contains(stderr, "Monitor summary") {
		t.Fatalf("opencode execution failed before monitor evidence was recorded; stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "Monitor summary") {
		t.Fatalf("stderr missing monitor summary: %q", stderr)
	}
	if !strings.Contains(stderr, "models.dev") && !strings.Contains(stderr, "opencode.ai") {
		t.Fatalf("stderr missing OpenCode host evidence: %q", stderr)
	}
	if !strings.Contains(stderr, "TLS:") && !strings.Contains(stderr, "HTTP:") {
		t.Fatalf("stderr missing TLS/HTTP monitor output: %q", stderr)
	}
}

func TestBoxMonitorModeAllowsHTTPTrafficButLogsWouldBlockVerdict(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteMonitorConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "allowed.example",
			Ports:    []int{443},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-sS", "http://example.com/",
	)
	if err != nil {
		t.Fatalf("monitor mode should allow blocked-policy traffic; stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("monitor mode curl output = %q, want Example Domain response body", stdout)
	}
	if !strings.Contains(stderr, "Monitor summary") {
		t.Fatalf("stderr missing monitor summary: %q", stderr)
	}
	if !strings.Contains(stderr, "WOULD_BLOCK") {
		t.Fatalf("stderr missing would_block verdicts: %q", stderr)
	}
}

func TestBoxMonitorModeAllowsHTTPSTrafficButLogsWouldBlockVerdict(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteMonitorConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "allowed.example",
			Ports:    []int{443},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-sS", "https://example.com/",
	)
	if err != nil {
		t.Fatalf("monitor mode should allow blocked-policy https traffic; stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("monitor mode https curl output = %q, want Example Domain response body", stdout)
	}
	if !strings.Contains(stderr, "Monitor summary") {
		t.Fatalf("stderr missing monitor summary: %q", stderr)
	}
	if !strings.Contains(stderr, "WOULD_BLOCK") {
		t.Fatalf("stderr missing would_block verdicts: %q", stderr)
	}
	if !strings.Contains(stderr, "CONNECT example.com [WOULD_BLOCK]") {
		t.Fatalf("stderr missing proxied https CONNECT verdict: %q", stderr)
	}
}

func TestBoxMonitorModeAllowsTransparentHTTPSTrafficButLogsWouldBlockVerdict(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteMonitorConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "allowed.example",
			Ports:    []int{443},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
		"curl", "-sS", "https://example.com/",
	)
	if err != nil {
		t.Fatalf("monitor mode should allow blocked-policy transparent https traffic; stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("monitor mode transparent https curl output = %q, want Example Domain response body", stdout)
	}
	if !strings.Contains(stderr, "Monitor summary") {
		t.Fatalf("stderr missing monitor summary: %q", stderr)
	}
	if !strings.Contains(stderr, "WOULD_BLOCK") {
		t.Fatalf("stderr missing would_block verdicts: %q", stderr)
	}
	if !strings.Contains(stderr, "TLS:") || !strings.Contains(stderr, "example.com [WOULD_BLOCK]") {
		t.Fatalf("stderr missing transparent https TLS verdict: %q", stderr)
	}
}

func TestBoxMonitorModeAllowsProxiedHTTPSPathMismatchButLogsWouldBlockVerdict(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteMonitorConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "example.com",
			Ports:    []int{443},
			HTTP: &config.HTTPPolicyConfig{
				Path: []string{"/foo*"},
			},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"curl", "-sS", "https://example.com/",
	)
	if err != nil {
		t.Fatalf("monitor mode should allow proxied https path mismatch; stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("monitor mode proxied https path mismatch output = %q, want Example Domain response body", stdout)
	}
	if !strings.Contains(stderr, "Monitor summary") {
		t.Fatalf("stderr missing monitor summary: %q", stderr)
	}
	if !strings.Contains(stderr, "WOULD_BLOCK") {
		t.Fatalf("stderr missing would_block verdicts: %q", stderr)
	}
}

func TestBoxMonitorModeAllowsTransparentHTTPSPathMismatchButLogsWouldBlockVerdict(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	configPath := testenv.WriteMonitorConfigWithRules(t, []config.NetworkPolicyRule{
		{
			Hostname: "example.com",
			Ports:    []int{443},
			HTTP: &config.HTTPPolicyConfig{
				Path: []string{"/foo*"},
			},
		},
	})

	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, "--config", configPath, "--",
		"env", "-u", "HTTP_PROXY", "-u", "HTTPS_PROXY", "-u", "http_proxy", "-u", "https_proxy",
		"curl", "-sS", "https://example.com/",
	)
	if err != nil {
		t.Fatalf("monitor mode should allow transparent https path mismatch; stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
	if !strings.Contains(stdout, "Example Domain") {
		t.Fatalf("monitor mode transparent https path mismatch output = %q, want Example Domain response body", stdout)
	}
	if !strings.Contains(stderr, "Monitor summary") {
		t.Fatalf("stderr missing monitor summary: %q", stderr)
	}
	if !strings.Contains(stderr, "WOULD_BLOCK") {
		t.Fatalf("stderr missing would_block verdicts: %q", stderr)
	}
}

func runBoxSmoke(t *testing.T, payload ...string) string {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("integration smoke tests require Linux")
	}

	requireRootIfNeeded(t)

	binary := testenv.BuildBoxBinary(t)
	args := append([]string{"--"}, payload...)
	stdout, stderr, err := testenv.RunBinary(binary.ModuleRoot, binary.BinaryPath, true, args...)
	if err != nil {
		t.Fatalf("run box %v error = %v; stdout=%q stderr=%q", payload, err, stdout, stderr)
	}
	return stdout
}

func requireRootIfNeeded(t *testing.T) {
	t.Helper()

	if os.Geteuid() == 0 {
		return
	}

	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skipf("sudo not available for root-required smoke tests: %v", err)
	}

	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skipf("sudo privileges are required for smoke tests: %v", err)
	}
}

func firstNonLoopbackIPv4Prefix(t *testing.T, output string) netip.Prefix {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] != "inet" {
				continue
			}
			prefix, err := netip.ParsePrefix(fields[i+1])
			if err != nil || !prefix.Addr().Is4() {
				continue
			}
			if prefix.Addr().IsLoopback() {
				continue
			}
			return prefix.Masked()
		}
	}

	t.Fatalf("ip output = %q, want non-loopback ipv4 prefix", output)
	return netip.Prefix{}
}

func mustLookupIPv4(t *testing.T, host string) string {
	t.Helper()

	ips, err := net.LookupIP(host)
	if err != nil {
		t.Fatalf("LookupIP(%q) error = %v", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	t.Fatalf("LookupIP(%q) returned no IPv4 address", host)
	return ""
}

func startLocalWebSocketHandshakeServer(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
				http.Error(w, "missing websocket upgrade", http.StatusBadRequest)
				return
			}
			key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
			if key == "" {
				http.Error(w, "missing websocket key", http.StatusBadRequest)
				return
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Errorf("response writer does not support hijacking")
				return
			}
			conn, bufrw, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("Hijack() error = %v", err)
				return
			}
			defer conn.Close()

			accept := websocketAccept(key)
			if _, err := bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
				t.Errorf("WriteString(status) error = %v", err)
				return
			}
			if _, err := bufrw.WriteString("Upgrade: websocket\r\n"); err != nil {
				t.Errorf("WriteString(upgrade) error = %v", err)
				return
			}
			if _, err := bufrw.WriteString("Connection: Upgrade\r\n"); err != nil {
				t.Errorf("WriteString(connection) error = %v", err)
				return
			}
			if _, err := bufrw.WriteString("Sec-WebSocket-Accept: " + accept + "\r\n\r\n"); err != nil {
				t.Errorf("WriteString(accept) error = %v", err)
				return
			}
			if err := bufrw.Flush(); err != nil {
				t.Errorf("Flush() error = %v", err)
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, _ = conn.Write([]byte{0x88, 0x00})
		}),
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func gatewayIPForTest(t *testing.T) string {
	t.Helper()

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(t.Name()))
	thirdOctet := 1 + int(hasher.Sum32()%250)
	return fmt.Sprintf("100.96.%d.1", thirdOctet)
}
