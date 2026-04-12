# Structured Egress Policy Design

## Goal

Replace the current coarse `policy` schema with a structured egress policy that lets
operators express protocol-aware and port-aware rules for both DNS-resolved hostnames
and direct IPv4 destinations, including granular ICMP type/code controls.

## Scope

In scope:

- Replace `policy.allow_domains`, `policy.deny_domains`, and `policy.extra_allowed_cidrs`
  with a new structured `policy.egress` schema.
- Make `enforce` mode translate each policy rule into protocol-specific nftables state.
- Keep DNS-gated hostname admission, but bind admitted IPs to the exact permissions of the
  matching rule instead of a shared global allowlist.
- Add IPv4 CIDR rules for clients that connect directly to literal IPs.
- Add ICMP controls with explicit `type` and `code`.

Out of scope:

- IPv6 policy support
- Wildcard "allow all ports" or "allow all protocols" semantics
- Full nftables expression authoring in YAML
- New monitor summary formats for CIDR-based observations

## Configuration Model

The new schema replaces the old `policy` fields with a single structured list:

```yaml
policy:
  egress:
    - hostname: example.com
      transport:
        - protocol: tcp
          ports: [443]
        - protocol: udp
          ports: [443]
      icmp:
        - type: 8
          code: 0

    - cidr: 93.184.216.0/24
      transport:
        - protocol: tcp
          ports: [80, 443]
```

Each egress rule must specify exactly one selector:

- `hostname`
- `cidr`

Each rule may then grant one or both of:

- `transport`: protocol-specific TCP/UDP permissions with explicit destination ports
- `icmp`: explicit ICMP `type` and `code` tuples

There are no implicit permissions. A rule with no `transport` and no `icmp` is invalid.

## Matching Semantics

### Hostname Rules

- `hostname` uses the current normalized suffix-match behavior.
- A rule for `example.com` matches both `example.com` and `api.example.com`.
- Hostname rules participate in DNS admission for `enforce` mode.
- When DNS returns A records for an allowed hostname, each returned IPv4 address is
  attached to the permissions of every matching hostname rule.

### CIDR Rules

- `cidr` is IPv4-only.
- CIDR rules do not participate in DNS admission.
- CIDR rules are translated directly into static nftables sets at runtime startup.
- CIDR rules are intended for clients that connect to literal IPv4 addresses.

### Overlap

- If multiple hostname rules match a resolved name, the destination IP receives the union
  of the matched permissions.
- Hostname-derived permissions and CIDR-derived permissions are independent sources of
  admission. If either path produces a matching nftables accept rule, the packet is allowed.

## Firewall Structure

`enforce` mode currently uses one shared `allow_v4` set. That model is replaced with
runtime-owned per-rule sets plus protocol-specific accept rules.

For each `policy.egress` entry, the runtime creates one IPv4 destination set, for example:

- `egress_0_v4`
- `egress_1_v4`

For `hostname` rules:

- the set starts empty
- the DNS resolution callback inserts resolved IPv4 addresses into the set for each matching rule

For `cidr` rules:

- the set is populated at firewall creation time with the configured IPv4 prefix

The `forward` chain then gets one or more accept rules per policy entry:

- `ip daddr @egress_0_v4 tcp dport { 443 } accept`
- `ip daddr @egress_0_v4 udp dport { 443 } accept`
- `ip daddr @egress_0_v4 icmp type 8 code 0 accept`

Global `enforce` behavior stays otherwise consistent:

- DNS interception remains enabled for sandbox traffic
- `ct state established,related accept` remains in place
- `forward` default policy remains `drop`
- postrouting masquerade remains enabled for sandbox IPv4 egress

## DNS Behavior

`enforce` mode keeps DNS as the admission gate for hostname rules:

- if a queried hostname matches at least one `hostname` rule, the DNS request may resolve
- otherwise the DNS server returns a denial response as it does today

When an allowed query resolves:

- only IPv4 A records are admitted into nftables state
- each admitted IP is inserted into every matching hostname rule set
- insertion failure for one IP leaves that IP unadmitted and does not broaden policy

AAAA handling stays conservative and out of scope for the new rule model because this design
remains IPv4-only.

## Validation Rules

Configuration must fail closed. Validation rejects:

- a rule with both `hostname` and `cidr`
- a rule with neither `hostname` nor `cidr`
- a `cidr` that is not valid IPv4
- a `transport` item whose protocol is not `tcp` or `udp`
- a `transport` item with an empty port list
- ports outside `1..65535`
- duplicated ports within the same transport item
- an `icmp` item with `type` or `code` outside `0..255`
- a rule with no `transport` and no `icmp`

Normalization rules:

- hostnames follow the current normalization and suffix-match logic
- ports are stored in deterministic sorted order for stable nft rendering and tests
- ICMP tuples are stored in deterministic order for stable rendering and tests

## Monitor Mode

This design changes enforcement semantics. Monitor mode stays hostname-oriented:

- existing hostname verdict labeling remains for observed DNS, HTTP, and TLS events
- CIDR rules do not change monitor summary rendering in this iteration

This avoids inventing CIDR-centric monitor reporting that the current collection path cannot
represent accurately.

## Code Structure

The change should remain within the existing package boundaries:

- `internal/config`: new YAML types and validation
- `internal/monitor`: adapt hostname-policy compilation to consume the hostname subset of `policy.egress`
- `internal/firewall`: replace shared allowlist rendering with per-rule sets and protocol-aware accept rules
- `internal/runtime`: track structured policy state, map DNS resolutions to matching rule sets, and emit
  dynamic nft insertion commands to the correct set
- `internal/dns`: keep current admission and resolution callbacks, but drive them from structured hostname rules
- `box.yaml` and README: document the new schema and remove legacy policy fields

## Error Handling

- Any invalid structured policy fails config validation before runtime mutation.
- Any nftables creation error fails startup.
- Any dynamic IP insertion error leaves that IP denied and does not widen permissions.
- Unknown or malformed hostnames stay denied when hostname allow rules are present.

## Testing Strategy

### Unit Tests

- `internal/config`
  - valid hostname and CIDR rules load successfully
  - invalid selector combinations fail
  - invalid CIDR, protocol, port, ICMP type, and ICMP code fail

- `internal/firewall`
  - renders one destination set per egress rule
  - renders TCP and UDP port-scoped accept rules
  - renders ICMP type/code-scoped accept rules
  - pre-populates CIDR sets for static IP rules

- `internal/runtime`
  - hostname resolutions insert IPs into the correct per-rule set
  - overlapping hostname rules union permissions across multiple sets
  - CIDR rules do not affect DNS admission
  - dynamic insertion failures stay fail-closed

- `internal/monitor`
  - hostname verdict logic still works against the hostname subset of the structured policy

### Integration Tests

- allowed `tcp/443` to a resolved hostname succeeds in `enforce`
- the same hostname on a disallowed port fails
- direct IPv4 access succeeds only when covered by a matching `cidr` transport rule
- ICMP echo request succeeds only when explicitly allowed
- an unconfigured ICMP type/code remains blocked

## Migration

- Remove support for the legacy policy fields instead of carrying dual schemas.
- Update the default `box.yaml` to use `policy.egress`.
- Update test fixtures and README examples to the new format.

This is intentionally a breaking config change in exchange for a smaller and less ambiguous
runtime.
