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

`box.yaml` now supports two network modes:

- `monitor` for observation plus summary output
- `enforce` for DNS-gated egress, dynamic IP allowlisting from allowed DNS answers, and
  `policy.extra_allowed_cidrs` bootstrap exceptions

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
