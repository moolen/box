# gvisor-net Rebuild Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the lost `gvisor-net` repository so `box` is strictly compatible with the recovered CLI, config, runtime behavior, and fixes.

**Architecture:** Recreate the project as a small Go module with narrow internal packages for config, rootfs, netns, firewall, DNS, proxy, gVisor, init shim, and runtime orchestration. Drive the rebuild with TDD so the recovered contract is pinned before runtime integration work, then verify with unit tests, integration smoke tests, and manual root-required checks.

**Tech Stack:** Go, Cobra, YAML (`gopkg.in/yaml.v3`), `runsc`, Linux namespaces, `ip`, `nft`, standard library networking, Go testing

---

## File Structure

Planned repository layout and ownership:

- `go.mod`: module definition and external dependencies.
- `README.md`: prerequisites, usage, build/test workflows, compatibility notes.
- `Makefile`: `build` and `test` targets; builds both runtime binaries.
- `box.yaml`: exact recovered default config.
- `cmd/box/main.go`: CLI entrypoint.
- `cmd/box/root.go`: root command, persistent `--config`, `run` subcommand, payload parsing.
- `cmd/box/run_test.go`: CLI contract tests.
- `internal/config/config.go`: config types, defaults, and validation.
- `internal/config/load.go`: YAML loading and path resolution.
- `internal/config/config_test.go`: config tests.
- `internal/rootfs/plan.go`: rootfs plan generation.
- `internal/rootfs/apply.go`: bundle/rootfs staging.
- `internal/rootfs/rootfs_test.go`: rootfs tests.
- `internal/netns/netns.go`: network namespace and veth lifecycle.
- `internal/netns/netns_test.go`: name-planning tests that avoid host mutation.
- `internal/firewall/nft.go`: nftables rendering/application.
- `internal/firewall/route.go`: policy-routing rendering/application.
- `internal/firewall/nft_test.go`: firewall tests.
- `internal/dns/server.go`: DNS forwarder.
- `internal/dns/server_test.go`: DNS tests.
- `internal/proxy/http.go`: HTTP peek proxy.
- `internal/proxy/tls.go`: TLS ClientHello/SNI peek proxy.
- `internal/proxy/proxy_test.go`: proxy tests.
- `internal/gvisor/spec.go`: OCI bundle spec generation.
- `internal/gvisor/run.go`: `runsc` invocation.
- `internal/gvisor/gvisor_test.go`: spec and invocation tests.
- `internal/runtime/runtime.go`: orchestration entrypoint.
- `internal/runtime/cleanup.go`: manifest-driven teardown.
- `internal/runtime/runtime_test.go`: runtime orchestration tests.
- `internal/initshim/main.go`: init shim binary.
- `integration/testenv/testenv.go`: integration build helpers and module root detection.
- `integration/testenv/testenv_test.go`: build-helper tests.
- `integration/box_smoke_test.go`: four recovered smoke tests.

Because the original `.git` metadata is gone, commit steps below should be treated as conditional. If the repository is reinitialized before implementation, execute the commit steps as written; otherwise, complete the code/test work and defer commits.

### Task 1: Bootstrap The Go Module And Top-Level Assets

**Files:**
- Create: `go.mod`
- Create: `README.md`
- Create: `Makefile`
- Create: `box.yaml`

- [ ] **Step 1: Write the top-level assets from the recovered contract**

Create:

```go
module gvisor-net

go 1.24

require (
	github.com/spf13/cobra v1.9.1
	gopkg.in/yaml.v3 v3.0.1
)
```

Create `Makefile` with:

```make
.PHONY: build test

build: bin
	go build -o ./bin/box ./cmd/box
	go build -o ./bin/box-initshim ./internal/initshim

test:
	go test ./... -v

bin:
	mkdir -p ./bin
```

Create `box.yaml` using the exact recovered file contents from the approved spec. Create `README.md` with prerequisites (`Linux`, `sudo`, `runsc`, `ip`, `nft`), usage examples (`box -- ...`, `box run -- ...`), and the note that `make build` produces both binaries.

- [ ] **Step 2: Run module setup checks**

Run: `go mod tidy`

Expected: `go.sum` is created and `go mod tidy` exits successfully.

- [ ] **Step 3: Verify top-level build surfaces the expected current failures**

Run: `make build`

Expected: build fails because `./cmd/box` and `./internal/initshim` do not exist yet.

- [ ] **Step 4: Commit**

Run:

```bash
git add go.mod go.sum README.md Makefile box.yaml
git commit -m "chore: restore top-level project assets"
```

### Task 2: Rebuild Config Loading And Validation

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/load.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write failing config tests**

Create tests covering:

```go
func TestLoadDefaultsFromRecoveredBoxYAML(t *testing.T) {}
func TestLoadResolvesWorkdirRelativeToInvocationDir(t *testing.T) {}
func TestValidateRejectsTransparentProxyMITMAtRuntimeBoundary(t *testing.T) {}
func TestDNSBindAddrAutoUsesSentinelValueUntilRuntimePlanning(t *testing.T) {}
```

Check that parsing preserves fields like:

```go
if got.Network.Subnet != "100.96.0.0/30" {
	t.Fatalf("subnet = %q, want %q", got.Network.Subnet, "100.96.0.0/30")
}
```

- [ ] **Step 2: Run config tests to verify they fail**

Run: `go test ./internal/config -run TestLoadDefaultsFromRecoveredBoxYAML -v`

Expected: FAIL because the package does not exist yet.

- [ ] **Step 3: Write minimal config implementation**

Implement a `Config` struct mirroring the recovered YAML:

```go
type Config struct {
	Sandbox SandboxConfig `yaml:"sandbox"`
	Network NetworkConfig `yaml:"network"`
	Policy  PolicyConfig  `yaml:"policy"`
	Mounts  MountsConfig  `yaml:"mounts"`
	Docker  DockerConfig  `yaml:"docker"`
	GVisor  GVisorConfig  `yaml:"gvisor"`
}
```

Add `Load(path, cwd string) (Config, error)` and `ValidateRuntime(cfg Config) error` helpers. Resolve relative `workdir` values against the invocation directory. Keep `mitm` parseable in config but make `ValidateRuntime` reject it with a clear error.

- [ ] **Step 4: Run config tests to verify they pass**

Run: `go test ./internal/config -v`

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git add internal/config
git commit -m "feat: restore config loading and validation"
```

### Task 3: Rebuild The CLI Contract

**Files:**
- Create: `cmd/box/main.go`
- Create: `cmd/box/root.go`
- Create: `cmd/box/run_test.go`

- [ ] **Step 1: Write failing CLI tests**

Create tests for the recovered contract:

```go
func TestRootCommandAcceptsConfigFlag(t *testing.T) {}
func TestRootCommandRequiresPayloadAfterDoubleDash(t *testing.T) {}
func TestRunSubcommandAcceptsPayloadAfterDoubleDash(t *testing.T) {}
func TestResolveInitShimPrefersEnvThenSiblingThenFallback(t *testing.T) {}
func TestTTYDetectionReportsInteractiveStdStreams(t *testing.T) {}
```

Include a quoting assertion such as:

```go
got := shellCommand([]string{"bash", "-lc", "getent hosts example.com"})
want := "bash -lc 'getent hosts example.com'"
if got != want { t.Fatalf("shellCommand() = %q, want %q", got, want) }
```

- [ ] **Step 2: Run CLI tests to verify they fail**

Run: `go test ./cmd/box -v`

Expected: FAIL because the command package is incomplete.

- [ ] **Step 3: Implement the CLI**

Build a Cobra root command with:

```go
root.PersistentFlags().StringVar(&configPath, "config", "box.yaml", "path to config file")
root.Args = cobra.ArbitraryArgs
```

Support both:

```bash
box -- /bin/pwd
box run -- /bin/pwd
```

Add helpers for payload parsing, shell escaping, init-shim resolution, and TTY detection, but stub runtime execution behind an injected interface so tests can pass before the full runtime exists.

- [ ] **Step 4: Run CLI tests to verify they pass**

Run: `go test ./cmd/box -v`

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git add cmd/box
git commit -m "feat: restore box cli contract"
```

### Task 4: Rebuild The Init Shim And Rootfs Planner

**Files:**
- Create: `internal/initshim/main.go`
- Create: `internal/rootfs/plan.go`
- Create: `internal/rootfs/apply.go`
- Create: `internal/rootfs/rootfs_test.go`

- [ ] **Step 1: Write failing rootfs tests**

Create tests covering:

```go
func TestHostOverlayPlanIncludesRecoveredReadonlyBinds(t *testing.T) {}
func TestHostOverlayPlanIncludesWritableRuntimeDirs(t *testing.T) {}
func TestGeneratedEtcFilesUseGatewayDNSInMonitorMode(t *testing.T) {}
func TestResolveInitShimCopiesSiblingBinaryIntoBundle(t *testing.T) {}
```

Pin bind behavior like:

```go
wantRO := []string{"/bin", "/sbin", "/usr", "/lib", "/lib64"}
```

- [ ] **Step 2: Run rootfs tests to verify they fail**

Run: `go test ./internal/rootfs -v`

Expected: FAIL because the package is incomplete.

- [ ] **Step 3: Implement init shim and rootfs planning**

Implement `internal/initshim/main.go` as a minimal PID 1 shim that:

```go
func main() {
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// forward signals and reap children
}
```

Implement rootfs planning with generated files for `/etc/resolv.conf`, `/etc/hosts`, `/etc/hostname`, `/etc/passwd`, and `/etc/group`. Ensure `host-overlay` mounts the current repo path read-write at the configured workdir and adds the writable directories recovered from the spec.

- [ ] **Step 4: Run rootfs tests and build the init shim**

Run: `go test ./internal/rootfs -v`

Expected: PASS

Run: `go build -o ./bin/box-initshim ./internal/initshim`

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git add internal/initshim internal/rootfs
git commit -m "feat: restore init shim and rootfs planning"
```

### Task 5: Rebuild Netns Naming And Firewall Rendering

**Files:**
- Create: `internal/netns/netns.go`
- Create: `internal/netns/netns_test.go`
- Create: `internal/firewall/nft.go`
- Create: `internal/firewall/route.go`
- Create: `internal/firewall/nft_test.go`

- [ ] **Step 1: Write failing network and firewall tests**

Create tests for deterministic naming and nft rendering:

```go
func TestRuntimeIDProducesDeterministicResourceNames(t *testing.T) {}
func TestMonitorModeRendersScopedDNSRule(t *testing.T) {}
func TestMonitorModeRendersScopedTPROXYRuleWithIPFamilyToken(t *testing.T) {}
func TestIIFNameTokenIsNotQuoted(t *testing.T) {}
func TestPolicyRoutingPlanUsesLocalRouteToLoopback(t *testing.T) {}
```

Pin the TPROXY line:

```go
want := "tproxy ip to :18080"
```

- [ ] **Step 2: Run firewall tests to verify they fail**

Run: `go test ./internal/firewall -v`

Expected: FAIL because the package is incomplete.

- [ ] **Step 3: Implement deterministic naming and rendering**

Model names from a run ID:

```go
type Resources struct {
	NetNS     string
	HostVeth  string
	GuestVeth string
	TableName string
	FWMark    uint32
	RouteTable int
}
```

Implement renderers that generate exact nft and `ip rule` / `ip route` commands without mutating the host during unit tests. Separate pure rendering from command execution so runtime tests can capture intent safely.

- [ ] **Step 4: Run network and firewall tests to verify they pass**

Run: `go test ./internal/netns ./internal/firewall -v`

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git add internal/netns internal/firewall
git commit -m "feat: restore network naming and firewall intents"
```

### Task 6: Rebuild The DNS Forwarder

**Files:**
- Create: `internal/dns/server.go`
- Create: `internal/dns/server_test.go`

- [ ] **Step 1: Write failing DNS tests**

Create tests covering:

```go
func TestAutoBindInMonitorModeUsesGatewayIPAndDefaultPort(t *testing.T) {}
func TestExplicitBindPortInMonitorModeStillUsesGatewayIP(t *testing.T) {}
func TestForwarderReturnsUpstreamAnswer(t *testing.T) {}
func TestForwarderShutdownClosesListener(t *testing.T) {}
```

Drive the forwarder with a fake upstream UDP server inside the test.

- [ ] **Step 2: Run DNS tests to verify they fail**

Run: `go test ./internal/dns -v`

Expected: FAIL because the package is incomplete.

- [ ] **Step 3: Implement the DNS server**

Implement a small forwarder API such as:

```go
type Config struct {
	ListenAddr string
	Upstreams  []string
}

func Start(ctx context.Context, cfg Config, deps Deps) (*Server, error)
```

Ensure monitor-mode planning selects `<gatewayIP>:1053` when `bind_addr` is `auto`, and uses `<gatewayIP>:<requested port>` for explicit ports.

- [ ] **Step 4: Run DNS tests to verify they pass**

Run: `go test ./internal/dns -v`

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git add internal/dns
git commit -m "feat: restore dns forwarding"
```

### Task 7: Rebuild The Transparent Proxies

**Files:**
- Create: `internal/proxy/http.go`
- Create: `internal/proxy/tls.go`
- Create: `internal/proxy/proxy_test.go`

- [ ] **Step 1: Write failing proxy tests**

Create tests for:

```go
func TestHTTPProxyForwardsAndEmitsEvent(t *testing.T) {}
func TestTLSPeekExtractsSNIAndForwardsClientHello(t *testing.T) {}
func TestTransparentListenerFactoryUsesConfiguredPorts(t *testing.T) {}
func TestStartHTTPCloseDoesNotHangWithActiveUpstream(t *testing.T) {}
```

The shutdown regression test should keep an upstream connection open while the server closes.

- [ ] **Step 2: Run proxy tests to verify they fail**

Run: `go test ./internal/proxy -v`

Expected: FAIL because the package is incomplete.

- [ ] **Step 3: Implement HTTP/TLS peek proxies**

Implement an event callback surface:

```go
type Event struct {
	Protocol string
	Host     string
	SNI      string
}
```

Use bidirectional copy helpers that close both `client` and `upstream` on shutdown so the close path does not hang. Keep TLS in peek mode only.

- [ ] **Step 4: Run proxy tests to verify they pass**

Run: `go test ./internal/proxy -v`

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git add internal/proxy
git commit -m "feat: restore transparent proxy listeners"
```

### Task 8: Rebuild gVisor Bundle Generation And Invocation

**Files:**
- Create: `internal/gvisor/spec.go`
- Create: `internal/gvisor/run.go`
- Create: `internal/gvisor/gvisor_test.go`

- [ ] **Step 1: Write failing gVisor tests**

Create tests covering:

```go
func TestSpecUsesInitShimAsEntrypoint(t *testing.T) {}
func TestSpecIncludesConfiguredWorkdirEnvAndHostname(t *testing.T) {}
func TestRunnerInvokesRunscWithExpectedArgs(t *testing.T) {}
```

Use a fake command runner to capture `runsc` arguments.

- [ ] **Step 2: Run gVisor tests to verify they fail**

Run: `go test ./internal/gvisor -v`

Expected: FAIL because the package is incomplete.

- [ ] **Step 3: Implement OCI spec generation and runner**

Create an OCI spec model that wires:

```go
Process.Args = []string{"/box-initshim", "/bin/bash", "-ilc", "env"}
Process.Cwd = workdir
Hostname = cfg.Sandbox.Hostname
```

Implement a runner abstraction around `runsc run` so runtime code can inject real execution and tests can verify exact arguments.

- [ ] **Step 4: Run gVisor tests to verify they pass**

Run: `go test ./internal/gvisor -v`

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git add internal/gvisor
git commit -m "feat: restore gvisor bundle and runner"
```

### Task 9: Rebuild Runtime Orchestration And Safe Cleanup

**Files:**
- Create: `internal/runtime/runtime.go`
- Create: `internal/runtime/cleanup.go`
- Create: `internal/runtime/runtime_test.go`

- [ ] **Step 1: Write failing runtime tests**

Create tests for orchestration and hardening:

```go
func TestRunCreatesStateDirAndEventLog(t *testing.T) {}
func TestMonitorModeRewritesResolvConfToGatewayIP(t *testing.T) {}
func TestMonitorModeStartsDNSAndFirewallWithScopedResources(t *testing.T) {}
func TestNonMonitorModeDoesNotForceGatewayResolvConf(t *testing.T) {}
func TestDockerSettingsPropagateIntoRuntimeState(t *testing.T) {}
func TestRejectsMITMBeforeMutatingHostState(t *testing.T) {}
func TestCleanupOnlyDeletesManifestOwnedPaths(t *testing.T) {}
func TestCleanupOrderStopsRunnersBeforeNetworkTeardown(t *testing.T) {}
```

Model the cleanup safety test with a fake mounted repo path and assert runtime only removes the state dir it created.

- [ ] **Step 2: Run runtime tests to verify they fail**

Run: `go test ./internal/runtime -v`

Expected: FAIL because the package is incomplete.

- [ ] **Step 3: Implement runtime orchestration**

Design `Run` around injected dependencies:

```go
type Deps struct {
	Clock       func() time.Time
	RandomID    func() string
	CommandExec CommandExec
	DNS         DNSServerFactory
	Proxy       ProxyFactory
}
```

Persist a manifest under `/run/box/<id>` and tear down only the exact resources listed there. Keep cleanup reverse-ordered and best-effort, aggregating errors.

- [ ] **Step 4: Run runtime tests to verify they pass**

Run: `go test ./internal/runtime -v`

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git add internal/runtime
git commit -m "feat: restore runtime orchestration and safe cleanup"
```

### Task 10: Wire The CLI To The Runtime And Restore Integration Harness

**Files:**
- Modify: `cmd/box/root.go`
- Create: `integration/testenv/testenv.go`
- Create: `integration/testenv/testenv_test.go`
- Create: `integration/box_smoke_test.go`

- [ ] **Step 1: Write failing integration harness tests**

Create testenv tests for:

```go
func TestFindModuleRoot(t *testing.T) {}
func TestInvalidPackageReturnsBuildError(t *testing.T) {}
func TestGoBuildArgsDisableVCSStamping(t *testing.T) {}
```

Create smoke tests that build the binary and run:

```go
func TestBoxRunsPwd(t *testing.T) {}
func TestBoxRunsEnv(t *testing.T) {}
func TestBoxResolvesExampleDotComWithGetent(t *testing.T) {}
func TestBoxCanCurlExampleDotCom(t *testing.T) {}
```

- [ ] **Step 2: Run harness tests to verify they fail**

Run: `go test ./integration/testenv -v`

Expected: FAIL because the package is incomplete.

- [ ] **Step 3: Implement the harness and CLI runtime wiring**

Update the CLI to call the real runtime entrypoint. In `integration/testenv/testenv.go`, add:

```go
func goBuildArgs(pkgPath, output string) []string {
	return []string{"build", "-buildvcs=false", "-o", output, pkgPath}
}
```

Build the integration runner so it locates the module root, compiles `./cmd/box`, and invokes the binary with `sudo -E` only in the smoke tests that require root.

- [ ] **Step 4: Run fast integration-adjacent tests**

Run: `go test ./cmd/box ./integration/testenv -v`

Expected: PASS

- [ ] **Step 5: Commit**

Run:

```bash
git add cmd/box/root.go integration/testenv integration/box_smoke_test.go
git commit -m "feat: restore runtime wiring and integration harness"
```

### Task 11: End-To-End Verification And Documentation Polish

**Files:**
- Modify: `README.md`
- Modify: `Makefile`
- Modify: `cmd/box/main.go`
- Modify: `cmd/box/root.go`
- Modify: `internal/runtime/runtime.go`
- Modify: `integration/box_smoke_test.go`

- [ ] **Step 1: Run the full unit test suite**

Run: `go test ./... -count=1`

Expected: PASS for all non-root tests. Fix any remaining failures before moving on.

- [ ] **Step 2: Run the required root integration suite**

Run: `sudo -E go test ./integration -v -count 1`

Expected: PASS for:

```text
TestBoxRunsPwd
TestBoxRunsEnv
TestBoxResolvesExampleDotComWithGetent
TestBoxCanCurlExampleDotCom
```

- [ ] **Step 3: Run manual compatibility checks**

Run:

```bash
make build
sudo -E ./bin/box -- env
sudo -E ./bin/box -- bash -lc 'getent hosts example.com'
sudo -E ./bin/box -- curl http://example.com
```

Expected: commands succeed on a clean host state. If `sudo -E ./bin/box -- bash` is tested manually, it should be interactive rather than hanging.

- [ ] **Step 4: Polish docs to match the verified behavior**

Update `README.md` only if the verified behavior differs from the initial reconstruction text. Keep docs aligned with the exact supported workflows and known caveats.

- [ ] **Step 5: Commit**

Run:

```bash
git add README.md Makefile cmd/box internal integration
git commit -m "feat: complete gvisor-net rebuild verification"
```
