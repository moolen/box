# box Structured Egress Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the legacy coarse `policy` YAML with structured protocol-aware hostname and IPv4 CIDR egress rules, including ICMP type/code controls, and translate them into granular nftables enforcement.

**Architecture:** Keep `monitor` and `enforce` within the current package boundaries. `internal/config` becomes the authoritative schema for `policy.egress`, `internal/monitor` derives hostname verdicts from the hostname subset only, `internal/firewall` renders per-rule nft sets plus protocol-specific accept rules, and `internal/runtime` maps allowed DNS resolutions into the correct runtime-owned nft sets instead of one shared IPv4 allowlist.

**Tech Stack:** Go, YAML config loading, nftables command rendering, existing `internal/runtime` DNS callback flow, Go unit and integration tests.

---

## File Structure

- Modify: `internal/config/config.go`
  Responsibility: replace legacy policy fields with structured egress rule types.
- Modify: `internal/config/load.go`
  Responsibility: validate the new policy schema strictly and fail closed on malformed rules.
- Modify: `internal/config/config_test.go`
  Responsibility: pin YAML loading and runtime validation for structured egress rules.
- Modify: `internal/monitor/policy.go`
  Responsibility: derive hostname verdicts from `policy.egress` hostname rules only.
- Modify: `internal/monitor/collector_test.go`
  Responsibility: pin monitor verdict behavior after the policy schema change.
- Modify: `internal/firewall/nft.go`
  Responsibility: replace the shared `allow_v4` model with per-rule sets and protocol-aware accept rules.
- Modify: `internal/firewall/nft_test.go`
  Responsibility: pin nft command rendering for hostname-derived sets, static CIDR sets, TCP/UDP ports, and ICMP tuples.
- Modify: `internal/runtime/runtime.go`
  Responsibility: drive DNS allow decisions from structured hostname rules and insert learned IPs into the correct rule-owned nft sets.
- Modify: `internal/runtime/runtime_test.go`
  Responsibility: pin runtime DNS admission, overlapping hostname rule unioning, and dynamic nft insertion behavior.
- Modify: `integration/testenv/testenv.go`
  Responsibility: rewrite enforce-mode config fixtures to emit `policy.egress`.
- Modify: `integration/box_smoke_test.go`
  Responsibility: prove protocol/port-aware hostname and CIDR behavior in real sandbox runs.
- Modify: `README.md`
  Responsibility: document the new config shape and updated `enforce` semantics.
- Modify: `box.yaml`
  Responsibility: publish the new default policy schema and remove legacy fields.

### Task 1: Add Failing Config And Monitor Tests For Structured Egress Rules

**Files:**
- Modify: `internal/config/config_test.go`
- Modify: `internal/monitor/collector_test.go`
- Reference: `internal/config/config.go`
- Reference: `internal/monitor/policy.go`

- [ ] **Step 1: Write a failing config-load test for the new `policy.egress` YAML**

```go
func TestLoadStructuredEgressPolicy(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "box.yaml")
	cfgYAML := `
sandbox:
  rootfs: host-overlay
  workdir: .
network:
  mode: enforce
policy:
  egress:
    - hostname: example.com
      transport:
        - protocol: tcp
          ports: [443]
      icmp:
        - type: 8
          code: 0
    - cidr: 93.184.216.0/24
      transport:
        - protocol: udp
          ports: [443]
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := Load(cfgPath, t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(got.Policy.Egress) != 2 {
		t.Fatalf("policy.egress len = %d, want 2", len(got.Policy.Egress))
	}
}
```

- [ ] **Step 2: Write failing validation tests for mutually exclusive selector and invalid protocol/ICMP data**

```go
func TestValidateRejectsEgressRuleWithHostnameAndCIDR(t *testing.T) {
	cfg := Config{}
	cfg.Network.Mode = "enforce"
	cfg.Policy.Egress = []EgressRule{{
		Hostname: "example.com",
		CIDR:     "93.184.216.0/24",
		Transport: []TransportRule{{
			Protocol: "tcp",
			Ports:    []int{443},
		}},
	}}

	err := ValidateRuntime(cfg)
	if err == nil {
		t.Fatal("ValidateRuntime() error = nil, want selector rejection")
	}
}
```

- [ ] **Step 3: Add failing monitor tests that prove hostname verdicts come from the hostname subset of `policy.egress`**

```go
func TestEvaluateHostnameUsesStructuredHostnameRules(t *testing.T) {
	policy := config.PolicyConfig{
		Egress: []config.EgressRule{
			{
				Hostname: "example.com",
				Transport: []config.TransportRule{{
					Protocol: "tcp",
					Ports:    []int{443},
				}},
			},
			{
				CIDR: "93.184.216.0/24",
				Transport: []config.TransportRule{{
					Protocol: "tcp",
					Ports:    []int{80},
				}},
			},
		},
	}

	if got := EvaluateHostname(policy, "api.example.com"); got != VerdictAllow {
		t.Fatalf("EvaluateHostname() = %q, want allow from hostname rule", got)
	}
}
```

- [ ] **Step 4: Run the targeted config and monitor tests to verify they fail for the expected missing-schema reasons**

Run: `go test ./internal/config ./internal/monitor -run 'TestLoadStructuredEgressPolicy|TestValidateRejectsEgressRuleWithHostnameAndCIDR|TestEvaluateHostnameUsesStructuredHostnameRules' -count=1`

Expected: FAIL because `PolicyConfig` does not yet define `Egress`, rule structs, or structured hostname extraction.

- [ ] **Step 5: Commit the red tests**

```bash
git add internal/config/config_test.go internal/monitor/collector_test.go
git commit -m "test: add structured egress policy coverage"
```

### Task 2: Implement The Structured Policy Schema And Hostname Verdict Extraction

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/load.go`
- Modify: `internal/monitor/policy.go`
- Test: `internal/config/config_test.go`
- Test: `internal/monitor/collector_test.go`

- [ ] **Step 1: Add the new config types and remove the legacy policy fields**

```go
type PolicyConfig struct {
	Egress []EgressRule `yaml:"egress"`
}

type EgressRule struct {
	Hostname  string          `yaml:"hostname"`
	CIDR      string          `yaml:"cidr"`
	Transport []TransportRule `yaml:"transport"`
	ICMP      []ICMPRule      `yaml:"icmp"`
}

type TransportRule struct {
	Protocol string `yaml:"protocol"`
	Ports    []int  `yaml:"ports"`
}

type ICMPRule struct {
	Type int `yaml:"type"`
	Code int `yaml:"code"`
}
```

- [ ] **Step 2: Implement strict runtime validation for the new schema**

```go
func validateEgressRule(rule EgressRule) error {
	hasHostname := strings.TrimSpace(rule.Hostname) != ""
	hasCIDR := strings.TrimSpace(rule.CIDR) != ""
	if hasHostname == hasCIDR {
		return errors.New("each policy.egress rule must set exactly one of hostname or cidr")
	}
	if len(rule.Transport) == 0 && len(rule.ICMP) == 0 {
		return errors.New("each policy.egress rule must allow at least one transport or icmp tuple")
	}
	// Validate protocol, ports, cidr family, and ICMP bounds.
	return nil
}
```

- [ ] **Step 3: Add a helper in `internal/monitor/policy.go` that extracts normalized hostname rules from structured egress entries only**

```go
func hostnamePolicyRules(policy config.PolicyConfig) (allow []string, invalid bool) {
	for _, rule := range policy.Egress {
		if strings.TrimSpace(rule.Hostname) == "" {
			continue
		}
		normalized := NormalizeHostname(rule.Hostname)
		if normalized == "" {
			invalid = true
			continue
		}
		allow = append(allow, normalized)
	}
	return allow, invalid
}
```

- [ ] **Step 4: Run the focused config and monitor tests and verify they pass**

Run: `go test ./internal/config ./internal/monitor -run 'TestLoadStructuredEgressPolicy|TestValidateRejectsEgressRuleWithHostnameAndCIDR|TestEvaluateHostnameUsesStructuredHostnameRules' -count=1`

Expected: PASS

- [ ] **Step 5: Commit the schema and monitor implementation**

```bash
git add internal/config/config.go internal/config/load.go internal/monitor/policy.go internal/config/config_test.go internal/monitor/collector_test.go
git commit -m "feat: add structured egress policy schema"
```

### Task 3: Add Failing Firewall Tests For Protocol-Aware Sets And ICMP Rules

**Files:**
- Modify: `internal/firewall/nft_test.go`
- Reference: `internal/firewall/nft.go`

- [ ] **Step 1: Replace the old shared-allowset expectation with a failing per-rule render test**

```go
func TestEnforceModeRendersPerRuleSetsAndProtocolAwareAcceptRules(t *testing.T) {
	plan, err := BuildEnforcePlan(EnforcePlanInput{
		TableName:  "box_deadbeef",
		HostVeth:   "vethhdeadbeef",
		SubnetCIDR: "100.96.0.0/30",
		DNSPort:    1053,
		Rules: []EnforceRule{
			{
				SetName: "egress_0_v4",
				Transport: []TransportMatch{{
					Protocol: "tcp",
					Ports:    []int{443},
				}},
				ICMP: []ICMPMatch{{
					Type: 8,
					Code: 0,
				}},
			},
			{
				SetName: "egress_1_v4",
				CIDRs:   []string{"93.184.216.0/24"},
				Transport: []TransportMatch{{
					Protocol: "udp",
					Ports:    []int{443},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildEnforcePlan() error = %v", err)
	}

	mustContainCommand(t, plan.Commands, "nft add set inet box_deadbeef egress_0_v4 { type ipv4_addr; flags interval; }")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef forward iifname vethhdeadbeef ip saddr 100.96.0.0/30 ip daddr @egress_0_v4 tcp dport { 443 } accept")
	mustContainCommand(t, plan.Commands, "nft add rule inet box_deadbeef forward iifname vethhdeadbeef ip saddr 100.96.0.0/30 ip daddr @egress_0_v4 icmp type 8 code 0 accept")
}
```

- [ ] **Step 2: Add a failing test that CIDR rules pre-populate their set and hostname rules do not**

```go
func TestEnforceModePrepopulatesCIDRRuleSetsOnly(t *testing.T) {
	// Require "nft add element ... egress_1_v4 { 93.184.216.0/24 }"
	// and ensure the hostname-owned set is created but not prefilled.
}
```

- [ ] **Step 3: Add a failing test for the new dynamic element insertion command builder**

```go
func TestBuildEnforceAllowIPCommandTargetsSpecificRuleSet(t *testing.T) {
	got, err := BuildEnforceAllowIPCommand("box_deadbeef", "egress_0_v4", "93.184.216.34")
	if err != nil {
		t.Fatalf("BuildEnforceAllowIPCommand() error = %v", err)
	}
	want := "nft add element inet box_deadbeef egress_0_v4 { 93.184.216.34 }"
	if got != want {
		t.Fatalf("BuildEnforceAllowIPCommand() = %q, want %q", got, want)
	}
}
```

- [ ] **Step 4: Run the firewall tests to verify they fail for the expected API mismatch**

Run: `go test ./internal/firewall -run 'TestEnforceModeRendersPerRuleSetsAndProtocolAwareAcceptRules|TestEnforceModePrepopulatesCIDRRuleSetsOnly|TestBuildEnforceAllowIPCommandTargetsSpecificRuleSet' -count=1`

Expected: FAIL because `EnforcePlanInput` and the command builder still assume one shared `allow_v4` set.

- [ ] **Step 5: Commit the red firewall tests**

```bash
git add internal/firewall/nft_test.go
git commit -m "test: add protocol-aware firewall render coverage"
```

### Task 4: Implement Per-Rule nft Rendering For Transport And ICMP Rules

**Files:**
- Modify: `internal/firewall/nft.go`
- Test: `internal/firewall/nft_test.go`

- [ ] **Step 1: Add render-time rule types that describe one runtime-owned IPv4 set plus its allowed matches**

```go
type EnforceRule struct {
	SetName   string
	CIDRs     []string
	Transport []TransportMatch
	ICMP      []ICMPMatch
}

type TransportMatch struct {
	Protocol string
	Ports    []int
}

type ICMPMatch struct {
	Type int
	Code int
}
```

- [ ] **Step 2: Rewrite `BuildEnforcePlan` to render one nft set per rule and one accept rule per transport/ICMP tuple**

```go
for _, rule := range in.Rules {
	commands = append(commands,
		fmt.Sprintf("nft add set inet %s %s { type ipv4_addr; flags interval; }", in.TableName, rule.SetName),
	)
	for _, match := range rule.Transport {
		commands = append(commands,
			fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s ip daddr @%s %s dport { %s } accept",
				in.TableName, in.HostVeth, in.SubnetCIDR, rule.SetName, match.Protocol, joinPorts(match.Ports)),
		)
	}
	for _, tuple := range rule.ICMP {
		commands = append(commands,
			fmt.Sprintf("nft add rule inet %s forward iifname %s ip saddr %s ip daddr @%s icmp type %d code %d accept",
				in.TableName, in.HostVeth, in.SubnetCIDR, rule.SetName, tuple.Type, tuple.Code),
		)
	}
}
```

- [ ] **Step 3: Update `BuildEnforceAllowIPCommand` to take a specific set name**

```go
func BuildEnforceAllowIPCommand(tableName, setName, rawIP string) (string, error) {
	// Validate table, set name, and IPv4 address, then target the specific set.
}
```

- [ ] **Step 4: Run the targeted firewall tests and verify they pass**

Run: `go test ./internal/firewall -run 'TestEnforceModeRendersPerRuleSetsAndProtocolAwareAcceptRules|TestEnforceModePrepopulatesCIDRRuleSetsOnly|TestBuildEnforceAllowIPCommandTargetsSpecificRuleSet' -count=1`

Expected: PASS

- [ ] **Step 5: Commit the firewall implementation**

```bash
git add internal/firewall/nft.go internal/firewall/nft_test.go
git commit -m "feat: render structured egress nft rules"
```

### Task 5: Add Failing Runtime Tests For Structured DNS Admission And Dynamic Rule-Set Updates

**Files:**
- Modify: `internal/runtime/runtime_test.go`
- Reference: `internal/runtime/runtime.go`

- [ ] **Step 1: Replace the old shared-allowset runtime test with a failing hostname-rule-set insertion test**

```go
func TestEnforceModeAddsResolvedIPsToMatchingHostnameRuleSets(t *testing.T) {
	cfg := testConfig("enforce")
	cfg.Policy.Egress = []config.EgressRule{
		{
			Hostname: "allowed.example.com",
			Transport: []config.TransportRule{{
				Protocol: "tcp",
				Ports:    []int{443},
			}},
		},
	}

	exec := &recordingCommandExec{}
	_, err := Run(context.Background(), Request{Config: cfg, StateRoot: t.TempDir()}, Deps{
		Clock:       fixedClock,
		RandomID:    func() string { return "runtime-enforce-structured" },
		CommandExec: exec,
		MonitorPreflight: func(context.Context, MonitorPreflightRequest) error { return nil },
		DNS: func(_ context.Context, req DNSStartRequest) (Runner, error) {
			req.OnResolved(dns.Resolution{
				Hostname: "allowed.example.com",
				IPs:      []netip.Addr{netip.MustParseAddr("93.184.216.34")},
			})
			return noopRunner{}, nil
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	mustContainCall(t, exec.calls, "nft add element inet box_")
	mustContainCall(t, exec.calls, "egress_0_v4")
}
```

- [ ] **Step 2: Add a failing runtime test that overlapping hostname rules union permissions onto one resolved IP**

```go
func TestEnforceModeUnionsOverlappingHostnameRulePermissions(t *testing.T) {
	// One rule grants tcp/443, another grants icmp type 8 code 0 for example.com.
	// A resolved IP for api.example.com must be inserted into both runtime-owned sets.
}
```

- [ ] **Step 3: Add a failing runtime test that CIDR-only rules do not allow DNS names**

```go
func TestEnforceModeCIDRRulesDoNotAuthorizeDNSQueries(t *testing.T) {
	cfg := testConfig("enforce")
	cfg.Policy.Egress = []config.EgressRule{{
		CIDR: "93.184.216.0/24",
		Transport: []config.TransportRule{{
			Protocol: "tcp",
			Ports:    []int{443},
		}},
	}}
	// Assert req.AllowQuery("example.com") == false.
}
```

- [ ] **Step 4: Run the focused runtime tests and verify they fail**

Run: `go test ./internal/runtime -run 'TestEnforceModeAddsResolvedIPsToMatchingHostnameRuleSets|TestEnforceModeUnionsOverlappingHostnameRulePermissions|TestEnforceModeCIDRRulesDoNotAuthorizeDNSQueries' -count=1`

Expected: FAIL because runtime policy compilation, hostname matching, and dynamic insertion still target the legacy schema and shared set.

- [ ] **Step 5: Commit the red runtime tests**

```bash
git add internal/runtime/runtime_test.go
git commit -m "test: add structured runtime egress coverage"
```

### Task 6: Implement Structured Runtime Policy Compilation And DNS-Driven Set Updates

**Files:**
- Modify: `internal/runtime/runtime.go`
- Test: `internal/runtime/runtime_test.go`

- [ ] **Step 1: Add runtime helpers that compile `policy.egress` into hostname and CIDR enforce entries with deterministic set names**

```go
type compiledEgressRule struct {
	SetName   string
	Hostname  string
	CIDR      string
	Transport []firewall.TransportMatch
	ICMP      []firewall.ICMPMatch
}

func compileRuntimeEgress(policy config.PolicyConfig) []compiledEgressRule {
	// Normalize, sort, and assign egress_<index>_v4 names.
}
```

- [ ] **Step 2: Drive DNS admission from the compiled hostname rules only**

```go
func (rt *Runtime) enforceAllowQuery(policyCfg config.PolicyConfig) func(hostname string) bool {
	compiled := compileRuntimeEgress(policyCfg)
	return func(hostname string) bool {
		return anyHostnameRuleMatches(compiled, hostname)
	}
}
```

- [ ] **Step 3: Rewrite the DNS resolved callback to insert learned IPv4s into every matching hostname-owned set**

```go
func (rt *Runtime) enforceResolvedCallback(ctx context.Context, deps Deps) func(dns.Resolution) {
	compiled := rt.compiledEgress
	return func(event dns.Resolution) {
		for _, rule := range matchingHostnameRules(compiled, event.Hostname) {
			for _, addr := range event.IPs {
				if err := rt.allowResolvedIP(ctx, deps.CommandExec, rule.SetName, addr); err != nil {
					continue
				}
			}
		}
	}
}
```

- [ ] **Step 4: Feed the compiled rule list into `firewall.BuildEnforcePlan` and keep de-duplication scoped by set name plus IP**

```go
key := ruleSet + "|" + ip
if _, exists := rt.allowIPs[key]; exists {
	return nil
}
```

- [ ] **Step 5: Run the targeted runtime tests and verify they pass**

Run: `go test ./internal/runtime -run 'TestEnforceModeAddsResolvedIPsToMatchingHostnameRuleSets|TestEnforceModeUnionsOverlappingHostnameRulePermissions|TestEnforceModeCIDRRulesDoNotAuthorizeDNSQueries' -count=1`

Expected: PASS

- [ ] **Step 6: Commit the runtime implementation**

```bash
git add internal/runtime/runtime.go internal/runtime/runtime_test.go
git commit -m "feat: enforce structured egress rules at runtime"
```

### Task 7: Update Fixtures, Docs, And Integration Coverage For Hostname, CIDR, And ICMP Rules

**Files:**
- Modify: `integration/testenv/testenv.go`
- Modify: `integration/box_smoke_test.go`
- Modify: `box.yaml`
- Modify: `README.md`

- [ ] **Step 1: Rewrite `WriteEnforceConfig` to emit the new `policy.egress` YAML**

```go
func WriteEnforceConfig(t *testing.T, egressYAML string) string {
	content := fmt.Sprintf(`sandbox:
  ...
policy:
  egress:
%s
`, indentYAML(egressYAML, "    "))
	// Write file and return path.
}
```

- [ ] **Step 2: Add a failing integration test for hostname-scoped port enforcement**

```go
func TestBoxEnforceAllowsConfiguredHostnamePortOnly(t *testing.T) {
	// Allow example fixture host on tcp/443 only.
	// Prove the permitted request succeeds and a different port fails.
}
```

- [ ] **Step 3: Add a failing integration test for direct-IP CIDR allowance**

```go
func TestBoxEnforceAllowsDirectIPOnlyWhenCIDRRuleMatches(t *testing.T) {
	// Start an HTTP fixture, allow its IPv4 /32 or enclosing CIDR, and prove direct curl works.
}
```

- [ ] **Step 4: Add a failing integration test for ICMP tuple enforcement if host tooling is available**

```go
func TestBoxEnforceAllowsConfiguredICMPEchoOnly(t *testing.T) {
	// Use ping if present, allow type 8 code 0 to the fixture IP, and prove disallowed ICMP stays blocked.
}
```

- [ ] **Step 5: Update `box.yaml` and README examples to document `policy.egress` and remove legacy fields**

```yaml
policy:
  egress:
    - hostname: example.com
      transport:
        - protocol: tcp
          ports: [443]
    - cidr: 93.184.216.0/24
      icmp:
        - type: 8
          code: 0
```

- [ ] **Step 6: Run the targeted integration and doc-adjacent tests**

Run: `go test ./integration -run 'TestBoxEnforceAllowsConfiguredHostnamePortOnly|TestBoxEnforceAllowsDirectIPOnlyWhenCIDRRuleMatches|TestBoxEnforceAllowsConfiguredICMPEchoOnly|TestBoxEnforceBlocksDisallowedTraffic' -count=1`

Expected: PASS on hosts with the required Linux tooling; ICMP-specific test may skip cleanly if `ping` is unavailable.

- [ ] **Step 7: Commit the fixture, integration, and docs updates**

```bash
git add integration/testenv/testenv.go integration/box_smoke_test.go box.yaml README.md
git commit -m "docs: publish structured egress policy"
```

### Task 8: Run Full Verification

**Files:**
- Verify only: repo-wide

- [ ] **Step 1: Run the full unit and package test suite**

Run: `go test ./... -count=1`

Expected: PASS

- [ ] **Step 2: Run the Linux root-required integration suite**

Run: `sudo -E go test ./integration -v -count=1`

Expected: PASS or explicit SKIPs only for missing host prerequisites such as `docker`, `dockerd`, `skopeo`, or `ping`.

- [ ] **Step 3: Build the release binaries**

Run: `make build`

Expected: PASS and produce `./bin/box` plus `./bin/box-initshim`.
