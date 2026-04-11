# box In-Sandbox Docker Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `docker.enabled` start a real in-sandbox Docker daemon with daemon-level HTTP(S) proxy config, and always inject HTTP(S) proxy env vars into sandbox commands.

**Architecture:** Keep `dockerd` inside the sandbox and supervise it from the init shim. Generate Docker daemon config in the rootfs, extend the HTTP proxy to support explicit proxy semantics including CONNECT, inject proxy env vars in the OCI process env, and verify the resulting socket and env behavior through integration tests.

**Tech Stack:** Go, `runsc`, `dockerd`, Unix sockets, HTTP proxying, Go testing

---

## File Structure

- `cmd/box/root.go`: derive proxy env values and pass Docker-enabled runtime context into the sandbox launch path.
- `cmd/box/run_test.go`: pin executor/runtime behavior around proxy env injection and Docker-enabled launch setup.
- `internal/config/config.go`: existing Docker config shape remains authoritative.
- `internal/rootfs/plan.go`: add generated Docker daemon config planning.
- `internal/rootfs/apply.go`: stage the generated Docker daemon config into the bundle.
- `internal/rootfs/rootfs_test.go`: pin daemon config generation and writable Docker paths.
- `internal/gvisor/spec.go`: inject HTTP proxy env vars into sandbox process env.
- `internal/gvisor/gvisor_test.go`: pin final env behavior.
- `internal/initshim/main.go`: supervise optional in-sandbox `dockerd`, wait for socket, and terminate it cleanly.
- `internal/initshim/main_test.go`: pin Docker-enabled shim behavior.
- `internal/proxy/http.go`: support explicit proxy requests and CONNECT tunneling.
- `internal/proxy/proxy_test.go`: pin HTTP proxy CONNECT behavior.
- `integration/box_smoke_test.go`: add env and Docker smoke checks.
- `integration/testenv/testenv.go`: extend build helpers if Docker tests need extra binaries or host prechecks.

### Task 1: Write Failing Tests For Proxy Env Injection And Docker Config

**Files:**
- Modify: `internal/gvisor/gvisor_test.go`
- Modify: `internal/rootfs/rootfs_test.go`
- Modify: `integration/box_smoke_test.go`

- [ ] **Step 1: Add failing unit tests for proxy env injection**

Add tests that require `BuildSandboxSpec` to include:

```go
HTTP_PROXY=http://100.96.0.1:18080
HTTPS_PROXY=http://100.96.0.1:18080
NO_PROXY=127.0.0.1,localhost
```

- [ ] **Step 2: Add failing rootfs tests for daemon config generation**

Add tests that require a generated `/etc/docker/daemon.json` containing `proxies.http-proxy`,
`proxies.https-proxy`, and `proxies.no-proxy` when Docker is enabled.

- [ ] **Step 3: Add failing integration env smoke test**

Add a root-required test that runs `box -- /usr/bin/env` and requires `HTTP_PROXY=` and
`HTTPS_PROXY=` in the sandbox output.

- [ ] **Step 4: Run the targeted tests to verify they fail**

Run: `go test ./internal/gvisor ./internal/rootfs ./integration -run 'Test.*Proxy|Test.*Docker|TestBoxRunsEnv' -count=1`

Expected: FAIL because proxy envs and Docker daemon config are not generated yet.

### Task 2: Write Failing Tests For In-Sandbox dockerd And CONNECT Proxying

**Files:**
- Modify: `internal/initshim/main_test.go`
- Modify: `internal/proxy/proxy_test.go`
- Modify: `integration/box_smoke_test.go`

- [ ] **Step 1: Add failing init shim tests**

Add tests showing that when Docker is enabled the shim:

- starts `dockerd`
- waits for the configured socket
- then starts the payload

- [ ] **Step 2: Add failing proxy CONNECT tests**

Add a proxy test that dials the HTTP proxy, sends a `CONNECT host:443` request, and requires the
server to tunnel bytes to the upstream.

- [ ] **Step 3: Add failing Docker integration smoke test**

Add a root-required integration test that enables Docker and runs a command such as:

```bash
docker version
```

inside `box`, requiring success through the configured Unix socket.

- [ ] **Step 4: Run the targeted tests to verify they fail**

Run: `go test ./internal/initshim ./internal/proxy ./integration -run 'Test.*Docker|Test.*CONNECT' -count=1`

Expected: FAIL because `dockerd` is not started and the proxy does not yet support CONNECT.

### Task 3: Implement Proxy Env Injection And Docker Daemon Config

**Files:**
- Modify: `cmd/box/root.go`
- Modify: `internal/gvisor/spec.go`
- Modify: `internal/rootfs/plan.go`
- Modify: `internal/rootfs/apply.go`

- [ ] **Step 1: Derive proxy env values from gateway IP and proxy port**

Thread the proxy URL into the sandbox launch path and make the spec builder inject `HTTP_PROXY`,
`HTTPS_PROXY`, and `NO_PROXY` on every run.

- [ ] **Step 2: Generate `/etc/docker/daemon.json` when Docker is enabled**

Add a generated-file path in the rootfs plan with daemon proxy config, socket host config, and
data-root settings.

- [ ] **Step 3: Run targeted tests to verify they pass**

Run: `go test ./internal/gvisor ./internal/rootfs ./integration -run 'Test.*Proxy|Test.*Docker|TestBoxRunsEnv' -count=1`

Expected: PASS

### Task 4: Implement In-Sandbox dockerd Supervision And CONNECT Support

**Files:**
- Modify: `internal/initshim/main.go`
- Modify: `internal/proxy/http.go`
- Modify: `cmd/box/root.go`

- [ ] **Step 1: Extend the init shim to manage optional `dockerd`**

Use environment or launch metadata to decide whether to start `dockerd`, wait for the socket, and
terminate it after the payload exits.

- [ ] **Step 2: Extend the HTTP proxy for explicit proxy usage**

Implement direct HTTP forwarding plus CONNECT tunneling so both `HTTP_PROXY` and `HTTPS_PROXY`
work against the same listener.

- [ ] **Step 3: Re-run targeted tests**

Run: `go test ./internal/initshim ./internal/proxy ./integration -run 'Test.*Docker|Test.*CONNECT' -count=1`

Expected: PASS

### Task 5: Run Full Verification

**Files:**
- Modify: `README.md` if Docker runtime prerequisites need to be documented

- [ ] **Step 1: Run the full test suite**

Run: `go test ./... -count=1`

Expected: PASS

- [ ] **Step 2: Run the full root-required integration suite**

Run: `sudo -E go test ./integration -v -count=1`

Expected: PASS

- [ ] **Step 3: Build the binaries**

Run: `make build`

Expected: PASS and produce `./bin/box` plus `./bin/box-initshim`
