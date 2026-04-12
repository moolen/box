# Envoy Egress Policy Design

## Goal

Replace the current hand-rolled DNS and HTTP/TLS proxy enforcement path with an
Envoy-based outbound policy plane that:

- intercepts all sandbox HTTP, HTTPS, and DNS traffic
- performs TLS MITM using a per-sandbox runtime CA
- evaluates hostname, CIDR, port, and HTTP path policy centrally
- supports both transparent interception and explicit `HTTP_PROXY` / `HTTPS_PROXY`
- supports `monitor` mode with `would_allow` / `would_block` verdict logging

## Scope

In scope:

- Remove the existing top-level `policy` config section and replace it with
  `network.policy`.
- Replace the current custom proxy path with bundled Envoy plus a local Go policy
  service.
- Generate a per-sandbox CA during startup, inject its trust into the sandbox,
  and use it for Envoy TLS MITM.
- Randomize all Envoy listener ports on sandbox startup.
- Redirect sandbox HTTP, HTTPS, and DNS traffic into Envoy.
- Enforce protocol semantics: only HTTP/HTTPS over TCP, DNS over UDP, block all
  other UDP, pass ICMP.
- Support hostname and CIDR based policy rules, with optional HTTP path glob
  checks.
- Support `monitor` mode that permits traffic but logs the policy verdict that
  would have applied.

Out of scope:

- IPv6 policy support
- Non-HTTP application protocols over TCP
- Generic UDP allow rules other than DNS
- Inbound traffic policy
- Long-lived shared CA state across sandboxes

## Configuration Model

The existing top-level `policy` block is removed. Policy is defined only under
`network.policy`.

Example:

```yaml
network:
  mode: enforce
  policy:
    - hostname: example.com
      ports: [80, 443]
      http:
        path:
          - /foo/bar*

    - cidr: 192.168.1.0/24
      ports: [8443]

    - hostname: "*.example.org"
      ports: [443]
```

Each rule must specify exactly one selector:

- `hostname`
- `cidr`

Each rule must specify:

- `ports`

Each rule may also specify:

- `http.path`

Proposed YAML shape:

```yaml
type NetworkConfig struct {
    Mode   string               `yaml:"mode"`
    Subnet string               `yaml:"subnet"`
    DNS    DNSConfig            `yaml:"dns"`
    Envoy  EnvoyConfig          `yaml:"envoy"`
    Policy []NetworkPolicyRule  `yaml:"policy"`
}

type NetworkPolicyRule struct {
    Hostname string             `yaml:"hostname"`
    CIDR     string             `yaml:"cidr"`
    Ports    []int              `yaml:"ports"`
    HTTP     *HTTPPolicyConfig  `yaml:"http"`
}

type HTTPPolicyConfig struct {
    Path []string `yaml:"path"`
}
```

## Matching Semantics

### Rule Selection

- A rule matches only when its selector matches and the original destination
  port is present in `ports`.
- Ports are pure destination port selectors. They do not permit arbitrary TCP.
  They mean HTTP or HTTPS is allowed on those ports.
- If the traffic on a matched port is not valid HTTP or HTTPS, it is denied in
  `enforce` and logged as `would_block` in `monitor`.

### Hostname Rules

- `hostname` supports exact names and leading wildcard patterns such as
  `*.example.org`.
- For hostname rules, the effective hostname is validated across the signals that
  exist for the request:
  - explicit proxy request target or CONNECT authority
  - TLS SNI when present
  - HTTP `Host` or `:authority` after decryption
- For hostname policy, these values must be mutually consistent and must match
  the configured hostname selector. A mismatch is denied.
- `http.path` applies after plaintext HTTP parsing or after HTTPS MITM.

### CIDR Rules

- `cidr` is IPv4-only in this iteration.
- Literal IP requests are evaluated against CIDR rules by original destination
  IP and port.
- HTTPS to literal IPs is MITM’d as well.
- For CIDR rules, host header and SNI consistency checks are skipped.
- `http.path` may still be applied after request decryption for direct literal-IP
  HTTP and HTTPS traffic.

### HTTP Path Rules

- `http.path` supports glob matching.
- Path evaluation occurs only after the request is successfully classified and,
  for HTTPS, decrypted.
- If `http.path` is configured and no pattern matches the request path, the
  request is denied.

### Protocol Semantics

- TCP is allowed only for HTTP and HTTPS traffic.
- HTTP and HTTPS are allowed on any configured destination port.
- UDP is blocked except DNS.
- DNS is always evaluated through the Envoy DNS policy path.
- ICMP is passed through in both `monitor` and `enforce` for now.

## Runtime Architecture

Each sandbox starts two host-side runtime-owned processes:

- `envoy`
- `policyd`

`policyd` is a new local Go control-plane and policy-evaluation service that
owns:

- HTTP `ext_authz` decisions
- TCP `ext_authz` decisions
- DNS evaluation and upstream resolution
- certificate issuance and SDS responses
- verdict logging and event shaping

Envoy owns:

- listener sockets
- protocol detection
- TLS termination / MITM
- explicit forward proxy support
- transparent forwarding
- access logging and metadata propagation

## CA Bootstrap

On sandbox startup:

1. Generate a per-sandbox root CA keypair.
2. Store the CA material under the sandbox runtime state directory.
3. Inject the CA certificate into the sandbox filesystem and trust setup.
4. Expose the CA certificate path to the sandbox environment.
5. Serve leaf certificates to Envoy through `policyd` SDS endpoints.

Certificate behavior:

- Hostname-based requests receive leaf certificates with DNS SANs.
- Literal-IP HTTPS requests receive leaf certificates with IP SANs.
- Leaf certificates are minted on demand and scoped to the runtime CA.
- Failure to mint a required leaf certificate denies the request in `enforce`
  and logs `would_block` in `monitor`.

## Envoy Packaging

The repo owns Envoy packaging and bootstrap.

Requirements:

- `box` must not depend on a host-installed Envoy.
- The repo pins an Envoy version and stages the binary as part of the build or
  packaging flow.
- Startup must fail clearly if the bundled Envoy artifact is missing, invalid,
  or the version/checksum check fails.

Runtime assets written per sandbox:

- Envoy bootstrap config
- Envoy access log path
- randomized listener port manifest
- CA and leaf-cert cache paths
- `policyd` endpoint metadata

The runtime manifest should record:

- bundled Envoy version
- randomized Envoy ports
- `policyd` endpoint
- CA certificate path
- Envoy bootstrap path

## Listener Layout

All Envoy listener ports are randomized per sandbox startup.

Listeners:

- explicit proxy listener for `HTTP_PROXY` and `HTTPS_PROXY`
- transparent TCP listener for redirected outbound TCP traffic
- DNS UDP listener for redirected outbound DNS traffic

Sandbox env injection:

- `HTTP_PROXY=http://<gateway-ip>:<random-explicit-port>`
- `HTTPS_PROXY=http://<gateway-ip>:<random-explicit-port>`
- `NO_PROXY=127.0.0.1,localhost`

Transparent interception:

- All outbound sandbox TCP traffic is redirected to the transparent Envoy
  listener.
- All outbound sandbox UDP/53 traffic is redirected to the Envoy DNS listener.
- Original destination IP and port must be preserved so policy is evaluated
  against the real upstream target.

## Request Processing

### Explicit Proxy Traffic

- Plain HTTP proxy requests are parsed by Envoy and evaluated through HTTP
  `ext_authz`.
- CONNECT requests are not left as blind tunnels.
- CONNECT traffic is terminated into the same TLS MITM and decrypted HTTP policy
  path used for transparent HTTPS.

### Transparent HTTP

- If redirected TCP traffic is valid plaintext HTTP, Envoy parses it directly.
- The decrypted request metadata is sent to `policyd` HTTP `ext_authz`.
- `policyd` evaluates selector, port, hostname/IP consistency rules, and optional
  `http.path`.

### Transparent HTTPS

- If redirected TCP traffic is TLS, Envoy MITMs it with a runtime-issued leaf
  certificate.
- After decryption, the HTTP request is evaluated through the same HTTP
  `ext_authz` path.
- Transparent HTTPS supports hostname rules, wildcard hostname rules, and CIDR
  rules.
- Literal-IP HTTPS is also MITM’d so `http.path` rules can apply.

### Non-HTTP TCP

- If traffic on a configured port is neither valid plaintext HTTP nor HTTPS that
  yields an HTTP request after MITM, it is denied in `enforce`.
- In `monitor`, it is allowed to continue but logged as `would_block` with an
  `unsupported_protocol` reason.

## DNS Processing

- Sandbox UDP/53 is redirected into Envoy’s DNS listener.
- `policyd` remains the source of truth for DNS policy decisions and upstream
  resolution.
- In `enforce`, DNS requests are denied unless at least one hostname rule
  matches.
- In `monitor`, DNS requests resolve normally but log `would_allow` or
  `would_block`.
- CIDR rules do not participate in DNS admission.

## Firewall Behavior

### Enforce Mode

- Redirect all sandbox TCP egress into Envoy’s transparent listener.
- Redirect sandbox UDP/53 into Envoy’s DNS listener.
- Drop all other sandbox UDP traffic.
- Allow ICMP through.
- Keep established and related traffic acceptance and postrouting masquerade.

### Monitor Mode

- Apply the same redirection into Envoy for TCP and DNS.
- Allow supported traffic to proceed regardless of policy verdict.
- Keep other behavior consistent enough that monitor verdicts reflect real future
  enforcement behavior.

## Monitor Verdicts

`monitor` mode uses the same policy evaluator as `enforce` but does not block
supported traffic.

Logged verdicts:

- `would_allow`
- `would_block`

Suggested log attributes:

- mode
- verdict
- protocol
- hostname
- destination ip
- destination port
- method
- path
- sni
- host header
- rule selector and match source
- deny reason

Reasons should include at least:

- `no_matching_rule`
- `hostname_mismatch`
- `path_mismatch`
- `port_not_allowed`
- `unsupported_protocol`
- `dns_not_allowed`
- `mitm_cert_issue`

## Validation Rules

Configuration validation must reject:

- any remaining top-level `policy` section
- a rule with both `hostname` and `cidr`
- a rule with neither `hostname` nor `cidr`
- a rule with no ports
- duplicate ports within a rule
- ports outside `1..65535`
- invalid hostname syntax
- wildcard hostnames that are not leading-label wildcards
- invalid or non-IPv4 CIDRs
- an empty `http.path` entry

Normalization rules:

- hostnames are lowercased and normalized deterministically
- wildcard hostnames are stored in normalized form
- CIDRs are stored in canonical string form
- ports are sorted for stable rendering and test output
- `http.path` globs preserve user order unless a later implementation chooses a
  deterministic sort for logging

## Failure Handling

- Startup fails closed if CA generation fails.
- Startup fails closed if Envoy bootstrap rendering fails.
- Startup fails closed if bundled Envoy cannot be launched.
- Startup fails closed if `policyd` cannot be launched.
- In `enforce`, authz or SDS communication failure denies requests.
- In `monitor`, startup still fails if the policy path is unavailable because the
  runtime would otherwise produce meaningless verdicts.
- Request-scoped MITM certificate issuance failure denies in `enforce` and logs
  `would_block` in `monitor`.
- Cleanup must stop Envoy and `policyd` before tearing down firewall and netns
  state.

## Code Structure

Proposed package boundaries:

- `internal/config`
  - move schema from top-level `policy` to `network.policy`
  - validate and normalize rules
  - reject legacy config
- `internal/runtime`
  - orchestrate CA generation, randomized port selection, process startup,
    manifest expansion, and sandbox env injection
- `internal/firewall`
  - render nftables redirects for TCP and DNS, UDP blocking, and ICMP pass
- `internal/envoy`
  - manage bundled Envoy binary resolution, bootstrap rendering, and process
    lifecycle
- `internal/policyd`
  - implement HTTP/TCP `ext_authz`, DNS evaluator, SDS, rule evaluation, and
    verdict logging
- `internal/rootfs`
  - inject CA trust files into the generated rootfs
- `internal/gvisor`
  - ensure proxy env vars and trust-related env/file mounts are propagated into
    the sandbox

The existing `internal/proxy` package should be removed once Envoy replaces the
custom HTTP/TLS path. The existing hostname-only monitor compiler should either
be removed or reduced to log rendering helpers if `policyd` becomes the new
source of truth for verdict generation.

## Testing Strategy

### Unit Tests

- `internal/config`
  - accepts valid hostname rules, wildcard hostname rules, and CIDR rules
  - rejects legacy top-level `policy`
  - rejects invalid selector combinations, invalid ports, invalid hostnames, and
    invalid CIDRs
  - validates `http.path` glob entries

- `internal/firewall`
  - redirects TCP to the randomized Envoy transparent listener
  - redirects UDP/53 to the randomized Envoy DNS listener
  - blocks non-DNS UDP
  - passes ICMP

- `internal/runtime`
  - generates runtime CA assets
  - allocates randomized listener ports
  - injects `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`
  - records Envoy and `policyd` details in the manifest
  - fails closed when Envoy or `policyd` cannot start

- `internal/envoy`
  - renders bootstrap config with correct listeners, clusters, and local service
    endpoints
  - resolves bundled Envoy binary path and version metadata correctly

- `internal/policyd`
  - hostname exact and wildcard matching
  - CIDR matching for literal IP requests
  - hostname/SNI/authority consistency checks for hostname rules
  - path glob allow and deny decisions
  - monitor verdict rendering
  - DNS allow and deny decisions
  - unsupported protocol classification handling

### Integration Tests

- HTTP with and without `HTTP_PROXY`
- HTTPS with and without `HTTPS_PROXY`
- hostname matching by exact name and wildcard, with and without proxy env vars
- HTTP path allow and deny for hostname rules
- HTTPS path allow and deny for hostname rules
- HTTP and HTTPS to literal IPs under CIDR rules, including path allow and deny
- non-HTTP TCP to an allowed IP/port combination should block
- non-HTTP TCP to a non-matching policy should block
- UDP to an allowed hostname or port should block as unacceptable protocol
- DNS allowed hostname in `enforce`
- DNS denied hostname in `enforce`
- DNS in `monitor` resolves and logs `would_allow` / `would_block`
- hostname policy with mismatched SNI and host header should block
- ICMP to an allowed hostname passes
- ICMP to an unallowed hostname also passes for now
- startup randomizes Envoy listener ports per sandbox
- sandbox env contains the matching injected proxy variables

## Migration

- Remove support for the legacy top-level `policy` schema instead of supporting
  both formats.
- Replace the sample config in `box.yaml`.
- Update README examples to the new `network.policy` layout.
- Remove the existing custom transparent proxy implementation after Envoy-backed
  enforcement is in place.

## Open Implementation Notes

- The evaluator should be implemented once in `policyd` and shared between HTTP,
  TCP, DNS, and monitor verdict generation.
- The runtime should keep the CA scoped to one sandbox to minimize cross-sandbox
  trust leakage.
- Because all ports are potentially valid for HTTP or HTTPS, protocol detection
  must be content-based, not port-based.
