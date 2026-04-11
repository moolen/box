# box Cobra CLI and Release Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `cmd/box` into a clearer Cobra-based command structure without changing runtime behavior, then add GitHub Actions for CI and automatic tag-and-release on every push to `main`.

**Architecture:** Keep Cobra at the CLI boundary and keep sandbox/runtime orchestration behind the existing executor seam. Split `cmd/box` into focused command and request-assembly files, preserve compatibility for both `box -- ...` and `box run -- ...`, and add two GitHub workflows: one for test/build validation and one for release publication. The release workflow should create one deterministic tag and one GitHub Release per pushed merge commit to `main`.

**Tech Stack:** Go, Cobra, GitHub Actions, Git, tar/gzip, Go testing

---

## File Structure

- `cmd/box/main.go`: keep as the thin entrypoint that constructs and executes the root Cobra command.
- `cmd/box/root.go`: reduce to root-command wiring or replace with a more focused root-command file.
- `cmd/box/run.go`: create a dedicated `run` subcommand file if the current command wiring is split out.
- `cmd/box/request.go`: create a small helper layer that converts parsed command input into `runRequest`.
- `cmd/box/executor.go`: move `runtimeExecutor` and runtime-facing helpers here if splitting `root.go` makes that clearer.
- `cmd/box/run_test.go`: keep runtime/executor seam tests and update them to reflect the new file boundaries.
- `cmd/box/root_test.go`: add command-tree tests for root help, persistent flags, and direct payload execution if a new file improves clarity.
- `.github/workflows/ci.yml`: add CI workflow for build and test validation.
- `.github/workflows/release.yml`: add automatic tag-and-release workflow on pushes to `main`.
- `README.md`: document the Cobra command forms and the new CI/release behavior if user-facing usage or repository operations need to be described.

### Task 1: Pin Current CLI Behavior With Cobra-Facing Tests

**Files:**
- Modify: `cmd/box/run_test.go`
- Create: `cmd/box/root_test.go`

- [ ] **Step 1: Add failing tests for direct root-command execution**

Add tests that construct the root Cobra command and require:

```go
box -- /bin/true
```

to invoke the executor with the expected `runRequest`.

- [ ] **Step 2: Add failing tests for the `run` subcommand**

Add tests that require:

```go
box run -- /bin/true
```

to build the same runtime request as the root command path.

- [ ] **Step 3: Add failing tests for persistent flag and help behavior**

Add tests that pin:

- `--config` is available from both root and `run`
- missing payload returns the expected command error
- `box --help` and `box run --help` render successfully

- [ ] **Step 4: Run the targeted CLI tests to verify they fail**

Run: `go test ./cmd/box -run 'TestRootCommand|TestRunCommand|Test.*Help|Test.*Config|Test.*Payload' -count=1`

Expected: FAIL until the command wiring is separated cleanly enough for the tests to pass.

### Task 2: Refactor `cmd/box` Into Clear Cobra Command Units

**Files:**
- Modify: `cmd/box/main.go`
- Modify: `cmd/box/root.go`
- Create: `cmd/box/run.go`
- Create: `cmd/box/request.go`
- Create: `cmd/box/executor.go`
- Modify: `cmd/box/run_test.go`
- Modify: `cmd/box/root_test.go`

- [ ] **Step 1: Extract command-construction helpers**

Split the current mixed CLI/runtime code so the root command and `run` subcommand each have one
clear constructor and both route through shared request-building logic.

- [ ] **Step 2: Preserve compatibility for both command forms**

Keep:

```text
box -- <command...>
box run -- <command...>
```

working through the same executor path, including TTY detection, init shim resolution, and
`--config` handling.

- [ ] **Step 3: Move runtime-facing orchestration out of the Cobra wiring layer**

Place `runtimeExecutor`, DNS/proxy startup helpers, and related runtime orchestration into a file
that is command-agnostic so Cobra code remains responsible only for parsing and dispatch.

- [ ] **Step 4: Run the CLI package tests to verify they pass**

Run: `go test ./cmd/box -count=1`

Expected: PASS

- [ ] **Step 5: Commit the CLI refactor**

Run:

```bash
git add cmd/box
git commit -m "refactor: split box Cobra command wiring"
```

### Task 3: Pin Workflow And Release Artifact Behavior In Repo Tests And Fixtures

**Files:**
- Modify: `README.md`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write the workflow contract down in the repo**

Update `README.md` with the expected repository automation behavior:

- CI runs tests and builds on pull requests and pushes to `main`
- release automation runs on pushes to `main`
- releases are automatically tagged and published

- [ ] **Step 2: Decide and pin the release artifact shape**

Use one archive per Linux target containing both binaries, for example:

```text
box_linux_amd64.tar.gz
box_linux_arm64.tar.gz
SHA256SUMS
```

Each archive should contain:

```text
box
box-initshim
```

- [ ] **Step 3: Validate the release-tag format**

Use a deterministic tag format tied to the pushed commit, such as:

```text
v0.0.0-<commit-timestamp>-<short-sha>
```

so every push to `main` produces exactly one stable tag for that commit.

### Task 4: Implement CI Workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Add the CI workflow triggers**

Configure the workflow to run on:

- pull requests targeting `main`
- pushes to `main`

- [ ] **Step 2: Add the CI build and test steps**

Use GitHub Actions steps that:

1. check out the repo
2. set up Go 1.24
3. enable module/build caching
4. run `go test ./... -count=1`
5. run `make build`

- [ ] **Step 3: Review the workflow for repo-specific assumptions**

Confirm the workflow does not assume local-only tools or unpublished secrets beyond the default
GitHub token.

- [ ] **Step 4: Validate the YAML structure locally**

Run: `sed -n '1,240p' .github/workflows/ci.yml`

Expected: workflow includes the intended triggers and commands with no placeholder content.

### Task 5: Implement Automatic Release Workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Add a release workflow triggered on pushes to `main`**

The workflow should execute only for `main` pushes so normal pull requests do not publish tags or
releases.

- [ ] **Step 2: Build release archives for supported targets**

Cross-compile:

```text
linux/amd64
linux/arm64
```

and package `box` plus `box-initshim` into per-target `.tar.gz` archives.

- [ ] **Step 3: Create the tag and GitHub Release**

Implement workflow steps that:

1. derive the commit-based version tag
2. create and push the tag
3. create the GitHub Release
4. upload the built archives and checksum file as release assets

Prefer standard maintained GitHub Actions for release creation and asset upload rather than custom
API shell scripts unless the action abstraction blocks the required behavior.

- [ ] **Step 4: Validate the YAML and script logic**

Run: `sed -n '1,320p' .github/workflows/release.yml`

Expected: workflow shows concrete tag derivation, archive packaging, and release upload steps.

- [ ] **Step 5: Commit the workflow automation**

Run:

```bash
git add .github/workflows README.md
git commit -m "ci: add build test and release workflows"
```

### Task 6: Run Full Verification

**Files:**
- Modify: `README.md` only if the final implementation changes the user-facing command surface or repo operations beyond the approved design

- [ ] **Step 1: Run the full Go test suite**

Run: `go test ./... -count=1`

Expected: PASS

- [ ] **Step 2: Build the binaries**

Run: `make build`

Expected: PASS and produce `./bin/box` plus `./bin/box-initshim`

- [ ] **Step 3: Inspect the staged workflow files**

Run:

```bash
sed -n '1,240p' .github/workflows/ci.yml
sed -n '1,320p' .github/workflows/release.yml
```

Expected: concrete workflow definitions with no placeholders.

- [ ] **Step 4: Commit the final verification-safe state**

Run:

```bash
git add cmd/box .github/workflows README.md
git commit -m "feat: refactor box CLI and automate releases"
```
