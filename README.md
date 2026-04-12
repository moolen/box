# gvisor-net

Recovered bootstrap for the `box` sandbox runner project.

## Prerequisites

- Linux
- `sudo`
- `runsc`
- `ip` (iproute2)
- `nft` (nftables)

## Build and Test

```bash
make build
make test
```

`make build` produces both binaries:

- `./bin/box`
- `./bin/box-initshim`

## Usage

```bash
box -- <command...>
box run -- <command...>
```

In `monitor` mode, `box` prints a final traffic summary to `stderr` at the end of the run.

`box.yaml` supports two network modes:

- `monitor` for observation plus summary output; it does not restrict general egress
- `enforce` for structured `policy.egress` rules that admit:
  - hostname-scoped DNS resolutions, then dynamic IPv4 allowlisting into per-rule nft sets
  - direct IPv4 CIDR destinations for clients that connect by literal IP
  - TCP/UDP traffic only on explicitly listed destination ports
  - ICMP traffic only for explicitly listed `type`/`code` tuples

Example `policy.egress`:

```yaml
policy:
  egress:
    - hostname: example.com
      transport:
        - protocol: tcp
          ports: [443]
    - cidr: 203.0.113.7/32
      icmp:
        - type: 8
          code: 0
```

Integration tests cover:

- `pwd`
- `env`
- `getent hosts example.com`
- `curl http://example.com`
- read-only `/usr` behavior (writes are blocked)
- writable `/tmp`
- writable sandbox workdir
- isolation checks for mounts and sandbox privileges
- enforce-mode blocked DNS resolution
- enforce-mode nested Docker multi-stage builds on Linux hosts with `docker`, `dockerd`,
  and `skopeo` available

## Repository Automation

GitHub Actions automation is wired for the `main` branch:

- CI runs on pull requests targeting `main` and on pushes to `main`
- CI installs missing Linux integration-test host tooling as needed, reusing preinstalled
  Docker/daemon when available, and installs a pinned `runsc` release with checksum verification
  before running `go test ./... -count=1` and `make build`
- release automation runs on pushes to `main` and creates one deterministic commit-based tag
  per commit in the format `v0.0.0-<commit-timestamp>-<short-sha>`
- rerunning the release workflow reuses the existing tag and updates the existing GitHub Release
  for that commit instead of failing

Published release assets are:

- `box_linux_amd64.tar.gz`
- `box_linux_arm64.tar.gz`
- `SHA256SUMS`

Each archive contains:

- `box`
- `box-initshim`
