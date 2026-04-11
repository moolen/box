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

Integration tests cover:

- `pwd`
- `env`
- `getent hosts example.com`
- `curl http://example.com`
