# box In-Sandbox Docker Proxy Design

## Summary

`box` already runs payloads inside `runsc`, but the `docker` config block is still mostly inert.
Today it only affects rootfs planning by making the configured Docker data root writable inside
the sandbox. It does not start `dockerd`, does not wait for a Docker socket, and does not inject
proxy settings for either the payload or the daemon.

This design turns the Docker block into real runtime behavior. When `docker.enabled` is true,
`box` should start an in-sandbox `dockerd` before the user payload, wait for the configured Unix
socket when requested, and shut the daemon down when the payload exits. Separately, every sandbox
command should receive `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables so later
policy work can key off explicit proxy usage rather than relying only on transparent interception.

## Goals

- Start a real `dockerd` inside the sandbox when `docker.enabled` is true.
- Generate an in-sandbox Docker daemon config with daemon-level HTTP(S) proxy settings.
- Always inject `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` into the sandbox process env.
- Keep the proxy target on the host-managed sandbox gateway so host-side policy logic remains the
  choke point for HTTP traffic.
- Preserve the current `box` isolation and integration behavior for non-Docker commands.

## Non-Goals

- No host Docker socket mounting.
- No nested-container networking policy beyond the current config shape.
- No TLS MITM.
- No attempt to manage Docker images or daemon lifecycle on the host.

## Proxy Model

The current host-side HTTP proxy already handles direct HTTP forwarding and transparent HTTP
redirection. For explicit proxy env usage, it also needs to support CONNECT tunneling so
`HTTPS_PROXY=http://...` works for normal clients and for `dockerd` registry access.

The proxy target should be derived from the sandbox gateway IP and the configured HTTP proxy port:

- `HTTP_PROXY=http://<gateway-ip>:<http-port>`
- `HTTPS_PROXY=http://<gateway-ip>:<http-port>`
- `NO_PROXY=127.0.0.1,localhost`

These env vars should be injected for every sandbox command, regardless of whether the caller
explicitly configured them, because the goal is to make proxy routing the default command path for
future HTTP policy work.

## Docker Daemon Behavior

When `docker.enabled` is true:

1. `box` should stage `/etc/docker/daemon.json` in the sandbox rootfs.
2. That file should include:
   - `data-root` using `docker.data_root`
   - `hosts` containing the configured Unix socket
   - `proxies.http-proxy`
   - `proxies.https-proxy`
   - `proxies.no-proxy`
3. The init shim should start `dockerd` before launching the user payload.
4. If `docker.wait_for_socket` is true, the init shim should poll the configured socket until it
   accepts connections or `docker.ready_timeout` expires.
5. When the payload exits, the init shim should terminate `dockerd`, wait for it, and then exit
   with the payload status.

The daemon should run entirely inside the sandbox and use writable sandbox paths such as:

- `/var/lib/docker`
- `/run`
- `/var/run`

No host Docker socket should be shared into the sandbox.

## Rootfs and Spec Changes

The rootfs planner should gain generated-file support for `/etc/docker/daemon.json` when Docker is
enabled. The sandbox spec builder should gain env augmentation logic so every sandboxed process
gets:

- configured user env from `sandbox.env`
- default `PATH`
- injected proxy env vars

The env injection should be deterministic so unit tests can pin the final env list.

## Init Shim Changes

The current init shim supervises a single payload process. It should be extended to optionally
supervise `dockerd` plus the payload:

- start `dockerd` with its own process group
- optionally wait for the Unix socket
- start payload
- forward signals to both process groups
- when payload exits, terminate `dockerd` and reap both children

The shim should remain a no-op wrapper when Docker is disabled.

## Testing Strategy

Unit and orchestration tests should cover:

- proxy env injection into the sandbox spec
- Docker daemon config file generation
- init shim startup and socket-wait behavior
- runtime/rootfs planning for Docker-enabled runs
- HTTP proxy CONNECT support for explicit `HTTPS_PROXY` usage

Integration should add:

- an env smoke assertion that both `HTTP_PROXY` and `HTTPS_PROXY` are present
- a Docker-enabled smoke test that runs `docker version` or `docker info` inside `box` and proves
  the configured Unix socket is usable

## Verification

The change is complete when all of these succeed on a Linux host with `docker` and `dockerd`
installed:

- `go test ./... -count=1`
- `sudo -E go test ./integration -v -count=1`
- `make build`
