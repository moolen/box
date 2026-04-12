# box Envoy Egress Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current custom DNS and transparent HTTP/TLS proxy enforcement with bundled Envoy plus a local Go policy service that enforces `network.policy`, performs TLS MITM with a per-sandbox CA, injects proxy env vars automatically, and supports monitor-mode `would_allow` / `would_block` verdicts.

**Architecture:** `internal/config` becomes the source of truth for `network.policy` and Envoy-related runtime config. `internal/runtime` allocates randomized listener ports, generates CA/runtime assets, and starts `policyd` plus Envoy. `internal/firewall` redirects TCP and DNS to Envoy while blocking non-DNS UDP and passing ICMP. `internal/policyd` owns the reusable rule evaluator plus Envoy-facing `ext_authz`, SDS, and DNS decision endpoints. `internal/envoy` renders bootstrap/config and manages the bundled Envoy process. `cmd/box/executor.go` stops wiring the legacy proxy path and instead injects the runtime-provided proxy env and trust material into the sandbox spec.

**Tech Stack:** Go, YAML config loading, gVisor OCI spec generation, nftables command rendering, Envoy, gRPC, Envoy authz/SDS protobufs via Go modules, Go unit tests, Linux integration tests.

---

## File Structure

- Modify: `internal/config/config.go`
  Responsibility: move policy under `network.policy`, add Envoy config, remove legacy transparent-proxy policy schema.
- Modify: `internal/config/load.go`
  Responsibility: validate `network.policy`, reject legacy top-level `policy`, normalize hostnames/CIDRs/ports/path globs.
- Modify: `internal/config/config_test.go`
  Responsibility: pin config loading, normalization, and validation for the new schema.
- Create: `internal/pki/ca.go`
  Responsibility: generate a per-sandbox CA, mint DNS-SAN and IP-SAN leaf certs, and expose PEM helpers.
- Create: `internal/pki/ca_test.go`
  Responsibility: pin CA generation and certificate SAN behavior.
- Create: `internal/policyd/policy.go`
  Responsibility: evaluate hostname, wildcard, CIDR, port, and HTTP path rules independent of transport.
- Create: `internal/policyd/policy_test.go`
  Responsibility: pin selector matching, path glob handling, authority consistency, and monitor verdict reasons.
- Create: `internal/policyd/service.go`
  Responsibility: expose Envoy-facing `ext_authz`, SDS, and DNS decision endpoints plus verdict logging.
- Create: `internal/policyd/service_test.go`
  Responsibility: pin request mapping from Envoy metadata into policy decisions and emitted responses.
- Create: `internal/envoy/bootstrap.go`
  Responsibility: render the per-sandbox Envoy bootstrap with randomized listeners, clusters, and local service wiring.
- Create: `internal/envoy/bootstrap_test.go`
  Responsibility: pin listener and cluster rendering for transparent TCP, explicit proxy, and DNS paths.
- Create: `internal/envoy/process.go`
  Responsibility: resolve the bundled Envoy artifact, start/stop Envoy, and validate runtime prerequisites.
- Create: `internal/envoy/process_test.go`
  Responsibility: pin binary resolution, arg rendering, and startup failure paths.
- Modify: `internal/firewall/nft.go`
  Responsibility: redirect all TCP to Envoy, redirect UDP/53 to Envoy DNS, block other UDP, pass ICMP, and preserve policy-routing behavior.
- Modify: `internal/firewall/nft_test.go`
  Responsibility: pin the new nftables render for monitor and enforce modes.
- Modify: `internal/rootfs/plan.go`
  Responsibility: add generated trust-anchor files or bind targets needed to inject the runtime CA into the sandbox.
- Modify: `internal/rootfs/rootfs_test.go`
  Responsibility: pin trust-file generation and mount layout.
- Modify: `internal/gvisor/spec.go`
  Responsibility: keep proxy env injection sourced from runtime manifest fields and propagate CA-related env vars when required.
- Modify: `internal/gvisor/gvisor_test.go`
  Responsibility: pin injected `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and CA-related env entries.
- Modify: `internal/runtime/runtime.go`
  Responsibility: replace DNS/proxy runner orchestration with CA generation, port allocation, `policyd` startup, Envoy startup, manifest expansion, and updated monitor behavior.
- Modify: `internal/runtime/runtime_test.go`
  Responsibility: pin runtime manifest contents, startup ordering, failure handling, randomized ports, and cleanup ordering.
- Modify: `cmd/box/executor.go`
  Responsibility: remove legacy `internal/proxy` startup wiring and consume runtime-provided Envoy/proxy/trust information.
- Modify: `cmd/box/run_test.go`
  Responsibility: pin executor env injection and process orchestration after the Envoy switch.
- Modify: `integration/testenv/testenv.go`
  Responsibility: write new `network.policy` fixtures and support integration cases that need hostname, CIDR, and path rules.
- Modify: `integration/box_smoke_test.go`
  Responsibility: prove the new proxy env injection and core policy flows in real sandbox runs.
- Modify: `README.md`
  Responsibility: document bundled Envoy, `network.policy`, monitor semantics, and protocol coverage.
- Modify: `box.yaml`
  Responsibility: publish the new default config layout.
- Modify: `Makefile`
  Responsibility: stage or verify the bundled Envoy artifact as part of the local build flow.
- Delete: `internal/proxy/http.go`
  Responsibility: remove the superseded custom transparent HTTP proxy implementation.
- Delete: `internal/proxy/tls.go`
  Responsibility: remove the superseded custom transparent TLS inspector/proxy implementation.
- Delete: `internal/proxy/proxy_test.go`
  Responsibility: remove tests for the deleted custom proxy path.

### Task 1: Replace The Config Schema With `network.policy` And Pin The Migration

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/load.go`
- Modify: `internal/config/config_test.go`
- Modify: `box.yaml`
- Reference: `README.md`

- [ ] **Step 1: Write failing config-load tests for `network.policy` and legacy-policy rejection**

```go
func TestLoadNetworkPolicyRules(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: enforce
  policy:
    - hostname: example.com
      ports: [80, 443]
      http:
        path:
          - /foo/*
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got.Network.Policy) != 1 {
		t.Fatalf("network.policy len = %d, want 1", len(got.Network.Policy))
	}
}

func TestLoadRejectsLegacyTopLevelPolicy(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: enforce
policy:
  allow_domains: ["example.com"]
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(cfgPath, t.TempDir())
	if err == nil {
		t.Fatal("Load() error = nil, want legacy policy rejection")
	}
}
```

- [ ] **Step 2: Write failing validation tests for wildcard hostnames, CIDRs, ports, and path globs**

```go
func TestValidateRejectsInvalidNetworkPolicyRule(t *testing.T) {
	cfg := Config{}
	cfg.Network.Mode = "enforce"
	cfg.Network.Policy = []NetworkPolicyRule{{
		Hostname: "*.bad.*.example",
		Ports:    []int{0},
		HTTP: &HTTPPolicyConfig{
			Path: []string{""},
		},
	}}

	err := ValidateRuntime(cfg)
	if err == nil {
		t.Fatal("ValidateRuntime() error = nil, want invalid rule rejection")
	}
}
```

- [ ] **Step 3: Run the focused config tests to verify the current schema fails**

Run: `go test ./internal/config -run 'TestLoadNetworkPolicyRules|TestLoadRejectsLegacyTopLevelPolicy|TestValidateRejectsInvalidNetworkPolicyRule' -count=1`

Expected: FAIL because the current config shape still uses top-level `policy` and `TransparentProxyConfig`.

- [ ] **Step 4: Implement the new schema and remove the legacy policy fields**

```go
type NetworkConfig struct {
	Mode   string              `yaml:"mode"`
	Subnet string              `yaml:"subnet"`
	DNS    DNSConfig           `yaml:"dns"`
	Envoy  EnvoyConfig         `yaml:"envoy"`
	Policy []NetworkPolicyRule `yaml:"policy"`
}

type NetworkPolicyRule struct {
	Hostname string            `yaml:"hostname"`
	CIDR     string            `yaml:"cidr"`
	Ports    []int             `yaml:"ports"`
	HTTP     *HTTPPolicyConfig `yaml:"http"`
}
```

- [ ] **Step 5: Run the focused config tests and the existing package tests**

Run: `go test ./internal/config -count=1`

Expected: PASS

- [ ] **Step 6: Commit the config migration**

```bash
git add internal/config/config.go internal/config/load.go internal/config/config_test.go box.yaml
git commit -m "feat: move egress policy under network config"
```

### Task 2: Add A Reusable Policy Evaluator And Certificate Primitives

**Files:**
- Create: `internal/pki/ca.go`
- Create: `internal/pki/ca_test.go`
- Create: `internal/policyd/policy.go`
- Create: `internal/policyd/policy_test.go`
- Reference: `internal/config/config.go`

- [ ] **Step 1: Write failing CA tests for runtime-root creation and IP-SAN/DNS-SAN leaf minting**

```go
func TestIssueLeafIncludesIPSANForLiteralIP(t *testing.T) {
	ca, err := NewRuntimeCA("runtime-a")
	if err != nil {
		t.Fatalf("NewRuntimeCA() error = %v", err)
	}

	certPEM, _, err := ca.IssueLeaf(LeafRequest{IP: netip.MustParseAddr("203.0.113.7")})
	if err != nil {
		t.Fatalf("IssueLeaf() error = %v", err)
	}

	cert := mustParseLeafCert(t, certPEM)
	if got := cert.IPAddresses[0].String(); got != "203.0.113.7" {
		t.Fatalf("leaf IP SAN = %q, want 203.0.113.7", got)
	}
}
```

- [ ] **Step 2: Write failing policy-evaluator tests for hostname, wildcard, CIDR, port, and `http.path` matching**

```go
func TestEvaluateHTTPSHostnamePathRule(t *testing.T) {
	rules := []config.NetworkPolicyRule{{
		Hostname: "example.com",
		Ports:    []int{443, 8443},
		HTTP: &config.HTTPPolicyConfig{
			Path: []string{"/api/*"},
		},
	}}

	decision := Evaluate(Request{
		Protocol:        ProtocolHTTPS,
		DestinationPort: 8443,
		SNI:             "example.com",
		Authority:       "example.com",
		Path:            "/api/v1",
	}, rules, ModeEnforce)

	if decision.Verdict != VerdictAllow {
		t.Fatalf("Verdict = %q, want allow", decision.Verdict)
	}
}
```

- [ ] **Step 3: Run the new focused tests to verify the helpers do not exist yet**

Run: `go test ./internal/pki ./internal/policyd -run 'TestIssueLeafIncludesIPSANForLiteralIP|TestEvaluateHTTPSHostnamePathRule' -count=1`

Expected: FAIL because the packages and helpers do not exist yet.

- [ ] **Step 4: Implement the runtime CA and pure rule-evaluation helpers**

```go
type Decision struct {
	Verdict Verdict
	Reason  string
	Rule    string
}

func Evaluate(req Request, rules []config.NetworkPolicyRule, mode Mode) Decision {
	// Match selector and port, verify hostname consistency where required,
	// then enforce optional path globs.
	return Decision{}
}
```

- [ ] **Step 5: Run the package tests**

Run: `go test ./internal/pki ./internal/policyd -count=1`

Expected: PASS

- [ ] **Step 6: Commit the pure policy and PKI primitives**

```bash
git add internal/pki/ca.go internal/pki/ca_test.go internal/policyd/policy.go internal/policyd/policy_test.go
git commit -m "feat: add envoy policy evaluator primitives"
```

### Task 3: Replace Firewall Rendering With Envoy Redirection Semantics

**Files:**
- Modify: `internal/firewall/nft.go`
- Modify: `internal/firewall/nft_test.go`
- Reference: `internal/firewall/route.go`

- [ ] **Step 1: Write failing firewall tests for TCP redirect, UDP/53 redirect, non-DNS UDP block, and ICMP pass**

```go
func TestEnforceModeRedirectsTCPAndDNSAndBlocksOtherUDP(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:      "box_deadbeef",
		HostVeth:       "vethhdeadbeef",
		SubnetCIDR:     "100.96.0.0/30",
		DNSPort:        15353,
		TransparentPort: 19001,
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error: %v", err)
	}

	mustContainCommand(t, plan.Commands, "tcp redirect to :19001")
	mustContainCommand(t, plan.Commands, "udp dport 53 redirect to :15353")
	mustContainCommand(t, plan.Commands, "udp drop")
	mustContainCommand(t, plan.Commands, "icmp accept")
}
```

- [ ] **Step 2: Run the targeted firewall tests and confirm the old allowset model fails**

Run: `go test ./internal/firewall -run 'TestEnforceModeRedirectsTCPAndDNSAndBlocksOtherUDP' -count=1`

Expected: FAIL because the current plan still renders DNS gating plus `allow_v4` forwarding rules.

- [ ] **Step 3: Rewrite the nft plan inputs and renderers for Envoy redirection**

```go
type EnforcePlanInput struct {
	TableName       string
	HostVeth        string
	SubnetCIDR      string
	DNSPort         int
	TransparentPort int
}
```

- [ ] **Step 4: Run the firewall package tests**

Run: `go test ./internal/firewall -count=1`

Expected: PASS

- [ ] **Step 5: Commit the firewall rewrite**

```bash
git add internal/firewall/nft.go internal/firewall/nft_test.go
git commit -m "feat: redirect sandbox traffic into envoy"
```

### Task 4: Add Runtime Port Allocation, Manifest Expansion, CA Trust Injection, And Sandbox Env Plumbing

**Files:**
- Modify: `internal/runtime/runtime.go`
- Modify: `internal/runtime/runtime_test.go`
- Modify: `internal/rootfs/plan.go`
- Modify: `internal/rootfs/rootfs_test.go`
- Modify: `internal/gvisor/spec.go`
- Modify: `internal/gvisor/gvisor_test.go`
- Modify: `cmd/box/executor.go`
- Modify: `cmd/box/run_test.go`

- [ ] **Step 1: Write failing runtime tests for randomized listener ports, CA paths, and injected proxy env**

```go
func TestRunRecordsRandomizedEnvoyPortsAndCAAssets(t *testing.T) {
	cfg := testConfig("enforce")
	cfg.Network.Policy = []config.NetworkPolicyRule{{
		Hostname: "example.com",
		Ports:    []int{443},
	}}

	rt, err := Run(context.Background(), Request{Config: cfg, StateRoot: t.TempDir()}, Deps{
		Clock:    fixedClock,
		RandomID: func() string { return "runtime-a" },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if rt.Manifest.Envoy.TransparentPort == 0 || rt.Manifest.Envoy.ExplicitPort == 0 || rt.Manifest.Envoy.DNSPort == 0 {
		t.Fatalf("Envoy ports = %#v, want randomized non-zero ports", rt.Manifest.Envoy)
	}
	if strings.TrimSpace(rt.Manifest.CA.CertPath) == "" {
		t.Fatalf("CA cert path missing from manifest")
	}
}
```

- [ ] **Step 2: Write failing gVisor and executor tests for env/trust injection**

```go
func TestSandboxProxyEnvUsesRuntimeEnvoyPort(t *testing.T) {
	env := sandboxProxyEnv("100.96.0.1", 19001)
	if !containsString(env, "HTTP_PROXY=http://100.96.0.1:19001") {
		t.Fatalf("sandboxProxyEnv() = %#v, want runtime envoy port", env)
	}
}
```

- [ ] **Step 3: Run the focused runtime, rootfs, gVisor, and executor tests**

Run: `go test ./internal/runtime ./internal/rootfs ./internal/gvisor ./cmd/box -run 'TestRunRecordsRandomizedEnvoyPortsAndCAAssets|TestSandboxProxyEnvUsesRuntimeEnvoyPort' -count=1`

Expected: FAIL because the manifest and rootfs do not yet carry Envoy/CA state.

- [ ] **Step 4: Implement manifest structs, port allocation, CA file generation, and sandbox env helpers**

```go
type EnvoyRuntime struct {
	ExplicitPort    int    `json:"explicit_port"`
	TransparentPort int    `json:"transparent_port"`
	DNSPort         int    `json:"dns_port"`
	BootstrapPath   string `json:"bootstrap_path"`
}

type CARuntime struct {
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}
```

- [ ] **Step 5: Run the package tests**

Run: `go test ./internal/runtime ./internal/rootfs ./internal/gvisor ./cmd/box -count=1`

Expected: PASS

- [ ] **Step 6: Commit the runtime plumbing**

```bash
git add internal/runtime/runtime.go internal/runtime/runtime_test.go internal/rootfs/plan.go internal/rootfs/rootfs_test.go internal/gvisor/spec.go internal/gvisor/gvisor_test.go cmd/box/executor.go cmd/box/run_test.go
git commit -m "feat: plumb envoy runtime assets into sandbox"
```

### Task 5: Add Bundled Envoy Bootstrap Rendering And Process Lifecycle

**Files:**
- Create: `internal/envoy/bootstrap.go`
- Create: `internal/envoy/bootstrap_test.go`
- Create: `internal/envoy/process.go`
- Create: `internal/envoy/process_test.go`
- Modify: `Makefile`

- [ ] **Step 1: Write failing bootstrap tests for listener and cluster rendering**

```go
func TestRenderBootstrapIncludesExplicitTransparentAndDNSListeners(t *testing.T) {
	cfg := BootstrapConfig{
		NodeID:          "runtime-a",
		ExplicitPort:    19001,
		TransparentPort: 19002,
		DNSPort:         19053,
		AuthzAddress:    "127.0.0.1:20001",
	}

	content, err := RenderBootstrap(cfg)
	if err != nil {
		t.Fatalf("RenderBootstrap() error = %v", err)
	}
	mustContainString(t, content, "19001")
	mustContainString(t, content, "19002")
	mustContainString(t, content, "19053")
	mustContainString(t, content, "ext_authz")
}
```

- [ ] **Step 2: Write failing process tests for bundled-binary resolution**

```go
func TestResolveBundledEnvoyPrefersSiblingBinary(t *testing.T) {
	got, err := ResolveBinary(BinaryLocator{
		ExecutablePath: "/tmp/bin/box",
		FileExists: func(path string) bool {
			return path == "/tmp/bin/envoy"
		},
	})
	if err != nil {
		t.Fatalf("ResolveBinary() error = %v", err)
	}
	if got != "/tmp/bin/envoy" {
		t.Fatalf("ResolveBinary() = %q, want /tmp/bin/envoy", got)
	}
}
```

- [ ] **Step 3: Run the focused Envoy tests**

Run: `go test ./internal/envoy -run 'TestRenderBootstrapIncludesExplicitTransparentAndDNSListeners|TestResolveBundledEnvoyPrefersSiblingBinary' -count=1`

Expected: FAIL because the package does not exist yet.

- [ ] **Step 4: Implement bootstrap rendering and process start/stop helpers**

```go
type StartRequest struct {
	BinaryPath    string
	BootstrapPath string
	LogPath       string
}
```

- [ ] **Step 5: Update `Makefile` so `make build` stages or verifies the bundled Envoy artifact**

```make
build: bin envoy
	go build -o ./bin/box ./cmd/box
	go build -o ./bin/box-initshim ./internal/initshim
```

- [ ] **Step 6: Run the package tests**

Run: `go test ./internal/envoy -count=1`

Expected: PASS

- [ ] **Step 7: Commit the Envoy bootstrap/process layer**

```bash
git add internal/envoy/bootstrap.go internal/envoy/bootstrap_test.go internal/envoy/process.go internal/envoy/process_test.go Makefile
git commit -m "feat: add bundled envoy runtime"
```

### Task 6: Implement `policyd` Envoy Endpoints And Runtime Startup/Cleanup

**Files:**
- Create: `internal/policyd/service.go`
- Create: `internal/policyd/service_test.go`
- Modify: `internal/runtime/runtime.go`
- Modify: `internal/runtime/runtime_test.go`
- Modify: `cmd/box/executor.go`
- Modify: `cmd/box/run_test.go`

- [ ] **Step 1: Write failing service tests for HTTP authz, TCP authz, DNS decisions, and monitor verdict logging**

```go
func TestCheckHTTPReturnsDeniedForPathMismatch(t *testing.T) {
	svc := NewService(ServiceConfig{
		Mode: ModeEnforce,
		Rules: []config.NetworkPolicyRule{{
			Hostname: "example.com",
			Ports:    []int{443},
			HTTP: &config.HTTPPolicyConfig{
				Path: []string{"/allowed/*"},
			},
		}},
	})

	resp, err := svc.CheckHTTP(context.Background(), makeHTTPCheckRequest("example.com", "/blocked"))
	if err != nil {
		t.Fatalf("CheckHTTP() error = %v", err)
	}
	if resp.Allowed {
		t.Fatalf("Allowed = true, want false")
	}
}
```

- [ ] **Step 2: Write failing runtime tests for startup ordering and fail-closed behavior**

```go
func TestRunStartsPolicyServiceBeforeEnvoy(t *testing.T) {
	var order []string
	_, err := Run(context.Background(), Request{Config: testConfig("enforce"), StateRoot: t.TempDir()}, Deps{
		RandomID: func() string { return "runtime-a" },
		StartPolicyService: func(context.Context, PolicyServiceStartRequest) (Runner, error) {
			order = append(order, "policyd")
			return noopRunner{}, nil
		},
		StartEnvoy: func(context.Context, EnvoyStartRequest) (Runner, error) {
			order = append(order, "envoy")
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"policyd", "envoy"}) {
		t.Fatalf("startup order = %#v, want policyd before envoy", order)
	}
}
```

- [ ] **Step 3: Run the focused tests**

Run: `go test ./internal/policyd ./internal/runtime ./cmd/box -run 'TestCheckHTTPReturnsDeniedForPathMismatch|TestRunStartsPolicyServiceBeforeEnvoy' -count=1`

Expected: FAIL because runtime still wires DNS and `internal/proxy` runners.

- [ ] **Step 4: Implement the service endpoints and replace the old runner dependencies**

```go
type Deps struct {
	CommandExec        CommandExec
	StartPolicyService PolicyServiceFactory
	StartEnvoy         EnvoyFactory
	MonitorPreflight   MonitorPreflightFunc
}
```

- [ ] **Step 5: Remove legacy proxy startup and consume the new runtime fields in the executor**

```go
deps := boxruntime.Deps{
	CommandExec:        hostCommandExec{},
	StartPolicyService: startPolicyService,
	StartEnvoy:         startEnvoyRunner,
	MonitorPreflight:   monitorPreflight,
}
```

- [ ] **Step 6: Run the package tests**

Run: `go test ./internal/policyd ./internal/runtime ./cmd/box -count=1`

Expected: PASS

- [ ] **Step 7: Commit the service integration**

```bash
git add internal/policyd/service.go internal/policyd/service_test.go internal/runtime/runtime.go internal/runtime/runtime_test.go cmd/box/executor.go cmd/box/run_test.go
git commit -m "feat: start policyd and envoy per sandbox"
```

### Task 7: Delete The Custom Proxy Path And Refresh Fixtures, Docs, And Integration Coverage

**Files:**
- Delete: `internal/proxy/http.go`
- Delete: `internal/proxy/tls.go`
- Delete: `internal/proxy/proxy_test.go`
- Modify: `integration/testenv/testenv.go`
- Modify: `integration/box_smoke_test.go`
- Modify: `README.md`
- Modify: `box.yaml`

- [ ] **Step 1: Rewrite integration fixtures to emit `network.policy` instead of legacy `policy`**

```go
func WriteEnforceConfig(t *testing.T, rules []string) string {
	// Emit network.policy YAML with hostname and CIDR examples used by tests.
}
```

- [ ] **Step 2: Add or update integration tests for the approved coverage**

```go
func TestBoxEnforceBlocksNonHTTPTCPOnAllowedPort(t *testing.T) {}
func TestBoxHTTPSHonorsPathRuleWithoutHTTPSProxy(t *testing.T) {}
func TestBoxHTTPSHonorsPathRuleWithHTTPSProxy(t *testing.T) {}
func TestBoxCIDRLiteralIPRuleAllowsHTTPSPath(t *testing.T) {}
func TestBoxBlocksUDPOnAllowedPort(t *testing.T) {}
```

- [ ] **Step 3: Remove the obsolete `internal/proxy` package and any references to `TransparentProxyConfig`**

Run: `rg -n 'internal/proxy|TransparentProxy|allow_domains|extra_allowed_cidrs'`

Expected: only docs or migration comments remain before the final cleanup pass.

- [ ] **Step 4: Run the targeted integration tests locally**

Run: `go test ./integration -run 'TestBoxRunsEnv|TestBoxEnforceBlocksDisallowedTraffic|TestBoxHTTPSHonorsPathRuleWithoutHTTPSProxy|TestBoxBlocksUDPOnAllowedPort' -count=1`

Expected: PASS on a Linux host with the required privileges and bundled Envoy artifact present.

- [ ] **Step 5: Update `README.md` and `box.yaml` to the new runtime behavior**

```yaml
network:
  mode: monitor
  policy:
    - hostname: example.com
      ports: [80, 443]
```

- [ ] **Step 6: Commit the cleanup, docs, and integration fixtures**

```bash
git add integration/testenv/testenv.go integration/box_smoke_test.go README.md box.yaml
git rm internal/proxy/http.go internal/proxy/tls.go internal/proxy/proxy_test.go
git commit -m "feat: replace custom proxy path with envoy policy plane"
```

### Task 8: Run Full Verification And Capture Residual Risks

**Files:**
- No new files
- Verify: repo-wide

- [ ] **Step 1: Run unit tests across the touched packages**

Run: `go test ./internal/config ./internal/pki ./internal/policyd ./internal/envoy ./internal/firewall ./internal/rootfs ./internal/runtime ./internal/gvisor ./cmd/box -count=1`

Expected: PASS

- [ ] **Step 2: Run the integration suite that exercises the new networking path**

Run: `go test ./integration -count=1`

Expected: PASS on Linux with root privileges, `runsc`, `ip`, `nft`, and the bundled Envoy artifact available.

- [ ] **Step 3: Run the full repo test suite**

Run: `go test ./... -count=1`

Expected: PASS

- [ ] **Step 4: Run the standard build**

Run: `make build`

Expected: succeeds and stages `./bin/box`, `./bin/box-initshim`, and the required Envoy artifact path.

- [ ] **Step 5: Review the final diff for accidental legacy references**

Run: `rg -n 'allow_domains|deny_domains|extra_allowed_cidrs|TransparentProxy|internal/proxy'`

Expected: no production-code matches remain.

- [ ] **Step 6: Commit the verification pass if it required code changes**

```bash
git add -A
git commit -m "test: finalize envoy egress policy verification"
```

## Notes For The Implementer

- Keep the evaluator fail-closed in `enforce`.
- In `monitor`, do not block supported requests; emit `would_allow` or `would_block` instead.
- Do not let destination port matching accidentally become generic TCP allowlisting.
- Keep literal-IP HTTPS on the same MITM path as hostname HTTPS so `http.path` rules remain enforceable.
- Preserve the existing cleanup discipline: stop long-lived runners before removing firewall or netns state.
- This repo currently has unrelated worktree changes. Do not revert them while implementing this plan.
