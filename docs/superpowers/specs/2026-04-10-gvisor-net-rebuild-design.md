# gvisor-net Rebuild Design

## Summary

Rebuild the lost `gvisor-net` repository from scratch while preserving the recovered `box`
runtime behavior and the CLI/config contract the user was relying on before the workspace was
wiped. The rebuilt project must be strictly compatible with the recovered `box.yaml` shape,
support both `box -- <command...>` and `box run -- <command...>`, and include the fixes that
were already identified during prior debugging.

The rebuild target is a working Linux-only sandbox runner built around gVisor, host-managed
network namespaces, nftables-based monitor mode, a host-side DNS forwarder, and transparent
HTTP/TLS interception in "peek" mode. The rebuilt tree should favor small, well-bounded
packages so the behavior can be verified and maintained without recreating the coupling that
made prior fixes risky.

## Repository State Constraint

The original repository metadata is gone. The current working directory is an empty directory,
not a Git repository, so this design document can be written to disk but cannot be committed
until the repository itself is reconstructed.

## Compatibility Goals

The rebuild must preserve these externally visible behaviors:

- Root command supports `--config` and defaults to `box.yaml`.
- `box -- <command...>` executes the payload command.
- `box run -- <command...>` remains supported as an equivalent subcommand path.
- `make build` produces both `./bin/box` and `./bin/box-initshim`.
- Local execution of `./bin/box` resolves a sibling `./bin/box-initshim` before falling back to
  `/usr/local/libexec/box-initshim`, while still honoring `BOX_INIT_SHIM_PATH` if set.
- The exact recovered `box.yaml` structure remains accepted, including `sandbox`, `network`,
  `policy`, `mounts`, `docker`, and `gvisor` sections and their known fields.
- Monitor mode DNS points the sandbox at the sandbox gateway address rather than `127.0.0.1`.
- Transparent proxy nftables rules use correct inet-family syntax with `tproxy ip to`.
- Proxy shutdown does not hang or leak listeners during teardown.
- Integration build helpers disable VCS stamping with `-buildvcs=false`.

## Out of Scope

The rebuild should not add new user-facing features beyond what is needed for strict
compatibility and the known fixes. In particular:

- No new policy-engine behavior beyond config parsing and placeholder fields.
- No TLS MITM implementation; `mitm` remains parseable at config level but rejected by runtime.
- No attempt to recreate old planning/spec history beyond the documents created for this
  reconstruction.

## Recovered Default Configuration

The canonical default configuration file must be recreated exactly as recovered from chat and
stored as `box.yaml`. That file defines:

- `sandbox.rootfs` modes `host-overlay` and `image`
- `sandbox.command_shell: /bin/bash -ilc`
- `network.mode` values including `monitor`, `enforce-dns`, `enforce-proxy`, and `deny-all`
- `network.subnet: 100.96.0.0/30`
- monitor-mode DNS forwarding with `bind_addr: auto`
- transparent proxy settings with `enabled`, `mode`, `http_port`, and `tls_port`
- placeholder policy lists
- optional extra bind mounts
- optional nested Docker settings
- gVisor runtime settings `platform`, `network`, and `debug`

## Architecture

The rebuild remains modular and reconstructs the same broad package boundaries that were in use
before the loss:

- `cmd/box`: Cobra CLI, root `--config`, `box -- ...`, `box run -- ...`, command assembly, and
  TTY detection.
- `internal/config`: default config values, YAML decoding, path resolution, and validation.
- `internal/runtime`: top-level orchestration and manifest-driven teardown.
- `internal/rootfs`: rootfs planning and bundle staging for `host-overlay` and `image` modes.
- `internal/netns`: netns, veth, address, and route creation.
- `internal/firewall`: nftables and policy-routing plan rendering/application.
- `internal/dns`: host-side DNS forwarder bound appropriately for monitor mode.
- `internal/proxy`: HTTP metadata interception and TLS ClientHello/SNI peek forwarding.
- `internal/gvisor`: OCI bundle generation and `runsc` process execution.
- `internal/initshim`: PID 1 shim copied into the bundle and used as the container entrypoint.
- `integration/testenv`: binary-build helpers and integration test setup.
- `integration`: end-to-end smoke tests.

Each package should expose a small API centered on the exact artifact it owns, such as a rootfs
plan, firewall intent, runtime manifest entry, or gVisor bundle description. The runtime package
is responsible for sequencing these components; the components themselves should not reach across
layers to clean up unrelated state.

## Runtime Flow

For each `box` invocation:

1. Load config from the root `--config` flag or the default `box.yaml`.
2. Resolve the payload command from arguments after `--`, supporting both the root command and
   the `run` subcommand.
3. Create a unique runtime ID and state directory under `/run/box/<id>`.
4. Build a rootfs plan and generated files, including `/etc/resolv.conf`, `/etc/hosts`,
   `/etc/hostname`, `/etc/passwd`, and `/etc/group`.
5. Create the network namespace and veth pair and assign the configured subnet.
6. Start the host-side DNS forwarder if enabled.
7. Apply nftables and policy-routing rules for the selected network mode.
8. Start transparent proxy listeners when configured.
9. Build the OCI bundle, resolve/copy the init shim, and execute `runsc`.
10. Tear everything down in reverse order using only the run manifest.

In monitor mode, the sandbox must see the sandbox gateway IP as its nameserver. DNS requests go
to the host-side DNS forwarder bound on that gateway IP and chosen port, and HTTP/TLS traffic is
intercepted on the host side before being forwarded to the original destination.

## Rootfs Behavior

`host-overlay` mode reuses host tooling read-only while bind-mounting the working tree
read-write. The reconstructed implementation should preserve the previously recovered host bind
set:

- read-only: `/bin`, `/sbin`, `/usr`, `/lib`, `/lib64`
- optional read-only when present: `/etc/alternatives`, `/opt`, `/snap`, `/nix`
- writable sandbox paths: `/tmp`, `/var/tmp`, `/run`, `/var/run`, `/var/cache`
- writable Docker state path when Docker is enabled

The current working tree path must be mounted read-write into the sandbox at the configured
workdir so commands like `box -- /bin/pwd` run inside the expected repository path.

## Networking and Firewall Behavior

The firewall layer must render nftables rules in an `inet` table with monitor-mode chains for
DNS and transparent proxying. Rules are scoped to the run's host-side veth interface and subnet.

Required behavior:

- DNS interception and proxy redirection are tied to the current run's host veth only.
- Transparent proxy rules include `tproxy ip to :<port>` to avoid the previously observed nft
  protocol conflict.
- Policy routing uses a run-specific fwmark and lookup table with a local route to `lo`.
- The runtime can reject unsupported modes like TLS MITM at start time before mutating state.

## DNS and Proxy Behavior

The DNS forwarder accepts sandbox DNS requests on the host side and forwards them to configured
upstreams such as `1.1.1.1:53` and `8.8.8.8:53`. In monitor mode, when `bind_addr` is `auto`,
the listener binds to the sandbox gateway IP with port `1053`. If a specific port is requested,
the runtime preserves that port while still using the sandbox gateway IP in monitor mode.

The HTTP proxy logs request metadata and forwards to the original destination. The TLS proxy
reads enough of the ClientHello to extract SNI and forwards the byte stream without full MITM.
Listener shutdown must be safe even while a client and upstream are still connected; both sides
of the splice should be closed when the server is shutting down so teardown does not hang.

## Cleanup and Hardening

Every run gets a unique manifest under `/run/box/<id>` that records only the resources created
for that run, including:

- runtime ID and state paths
- bundle path
- netns name
- host/sandbox veth names
- nft table name
- fwmark and routing table ID
- DNS/proxy listener addresses

Teardown is manifest-driven and reverse-ordered:

1. stop `runsc`
2. stop proxy listeners
3. stop DNS
4. remove nftables rules/table
5. remove policy-routing entries
6. remove veth pair
7. remove network namespace
8. remove runtime state directory

Hardening requirements:

- Cleanup must never recursively delete through mounted rootfs content or any bind-mounted host
  path.
- Cleanup may only operate on exact resources named in the current run manifest.
- If the intended names already exist but are not owned by the current manifest, the run must
  fail with a precise conflict error rather than attempting broad cleanup.
- Resource names should be deterministic from the runtime ID while remaining unique across runs.
- Teardown errors should be collected and surfaced, but must not expand scope beyond the current
  manifest.

## Interactive Usage Expectations

The rebuilt runtime must support manual testing patterns such as:

- `sudo -E ./bin/box -- bash`
- `sudo -E ./bin/box -- env`
- `sudo -E ./bin/box -- curl http://example.com`

Interactive prompt appearance may still depend on shell startup files and environment, but the
runtime must not block solely because the command is interactive. TTY detection and pass-through
should remain part of the CLI/runtime contract.

## Test Strategy

The rebuild must restore both unit and integration coverage around the recovered behavior.

Unit tests should pin:

- root-level `--config` handling
- command parsing for root command and `run` subcommand
- init shim path resolution order
- TTY detection behavior
- firewall intent rendering, including `tproxy ip to`
- monitor-mode DNS bind address and resolv.conf rewrite
- runtime manifest and deterministic naming behavior
- Docker state propagation
- rejection of unsupported transparent proxy modes
- proxy shutdown safety
- integration test build helper use of `-buildvcs=false`

Integration tests should restore these smoke cases exactly:

- `box -- /bin/pwd`
- `box -- /usr/bin/env`
- `box -- bash -lc 'getent hosts example.com'`
- `box -- curl http://example.com`

## Verification Gate

The reconstructed repository is only considered compatible when all of the following succeed on
a suitable Linux host with root and required tooling installed:

- `make build`
- `go test ./... -count=1`
- `sudo -E go test ./integration -v -count 1`
- manual `sudo -E ./bin/box -- curl http://example.com` on a clean host state

## Implementation Notes

The rebuild should recreate documentation and project scaffolding needed to operate the tool,
including at minimum:

- `README.md` documenting prerequisites, usage, and build/test workflows
- `Makefile` with `build` and `test` targets
- the exact default `box.yaml`

The implementation plan should follow TDD and rebuild the project in small, verifiable stages:
module skeleton, CLI/config, rootfs/init shim, networking/firewall, DNS/proxy, runtime cleanup,
and test restoration.
