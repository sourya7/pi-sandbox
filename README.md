# pi-sandbox

OS-level sandboxing and explicit filesystem/network permissions for [Pi](https://pi.dev/).

The extension covers model-facing `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls`. Bash subprocesses run through the repository's local [`sandbox-runtime`](./sandbox-runtime) fork using Seatbelt (`sandbox-exec`) on macOS and bubblewrap on Linux.

## Local setup

This checkout intentionally uses the git submodule as its runtime dependency; no published runtime release is required.

```bash
git clone --recurse-submodules <this-repository>
cd pi-sandbox
npm install
npm run runtime:setup
pi -e .
```

After changing runtime source:

```bash
npm run runtime:build
```

`package.json` uses `file:./sandbox-runtime`, and the lockfile records that link. Verify it with:

```bash
node -e "console.log(import.meta.resolve('@anthropic-ai/sandbox-runtime'))"
```

The result should point at `sandbox-runtime/dist/index.js` in this checkout.

### Platform prerequisites

| Platform | Requirements |
|---|---|
| macOS | `/usr/bin/sandbox-exec`; `rg`; normal system shell |
| Linux | `bwrap`, `socat`, `rg`; unprivileged user namespaces where bubblewrap requires them |

Typical `rg` installation:

```bash
brew install ripgrep                 # macOS/Homebrew
sudo port install ripgrep            # macOS/MacPorts
sudo apt install ripgrep bubblewrap socat  # Debian/Ubuntu
```

If a dependency is missing, agent tools fail closed instead of falling back to unsandboxed bash.

### Build the Linux `apply-seccomp` helper

This step is Linux-only. `apply-seccomp` blocks sandboxed commands from creating Unix-domain sockets, preventing access to host capabilities such as Docker, SSH/GPG agents, browser sockets, and local daemons. It is required when the policy uses:

```json
"network": {
  "allowAllUnixSockets": false
}
```

Published Sandbox Runtime packages normally contain prebuilt x64/arm64 helpers. This repository consumes the runtime source submodule directly, so generate the helper locally. `npm run runtime:setup` builds the TypeScript runtime but does **not** build this native helper.

The build needs Bun, `gcc`, `strip`, and the libseccomp development/static libraries. Install prerequisites with the appropriate OS package manager, for example:

```bash
# Debian/Ubuntu
sudo apt install gcc binutils libseccomp-dev

# Fedora/RHEL (glibc-static is needed by the script's -static link)
sudo dnf install gcc binutils libseccomp-devel glibc-static

# Arch
sudo pacman -S gcc binutils libseccomp

# Nix: enter a temporary build environment
nix shell nixpkgs#bun nixpkgs#gcc nixpkgs#binutils nixpkgs#libseccomp nixpkgs#glibc.static
```

Ensure `bun` is on `PATH`, then run from the repository root:

```bash
npm --prefix sandbox-runtime run build:seccomp
```

The output is architecture-specific:

```text
sandbox-runtime/vendor/seccomp/x64/apply-seccomp    # Node arch x64
sandbox-runtime/vendor/seccomp/arm64/apply-seccomp  # Node arch arm64
```

Verify the current architecture's helper:

```bash
arch_dir=$(node -p 'process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : "unsupported"')
test "$arch_dir" != unsupported
test -x "sandbox-runtime/vendor/seccomp/$arch_dir/apply-seccomp"
```

After building it, set `network.allowAllUnixSockets` to `false` in the active global and mode policies, then restart Pi. If the helper is missing while socket blocking is enabled, bash may fail with an error naming `vendor/seccomp/<arch>/apply-seccomp`. Keeping `allowAllUnixSockets: true` avoids the native helper but leaves host Unix sockets as a significant escape surface.

macOS does not use `apply-seccomp`; Seatbelt enforces Unix-socket restrictions there.

## Policy version 2

A simple configuration can live in trusted global configuration at `~/.pi/agent/sandbox.json` or in trusted project configuration at `.pi/sandbox.json`:

```json
{
  "policyVersion": 2,
  "enabled": true,
  "failClosed": true,
  "network": {
    "allowedDomains": ["github.com", "*.github.com", "registry.npmjs.org"],
    "deniedDomains": []
  },
  "filesystem": {
    "readScope": "home",
    "allowRead": ["."],
    "denyRead": ["~/.ssh", "~/.aws"],
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".env"]
  }
}
```

### Read scopes

| Scope | Behavior |
|---|---|
| `home` | Protect the user's home directory and reopen configured paths. Recommended default. Paths outside home remain readable unless hard-denied. |
| `strict` | Protect filesystem root and reopen configured/runtime-bootstrap paths. |
| `open` | No implicit protected region; only explicit hard denies. |

Within the protected region, priority is:

1. `denyRead` — authoritative hard deny; no prompt.
2. `allowRead` or `allowWrite` — allowed without prompting.
3. Anything else — prompt when the path is known, otherwise fail closed.

`allowWrite` necessarily implies read access, except below a more-specific hard deny. Hard read denies are also protected from writes/renames so a process cannot move a secret into a readable location.

Literal `allowRead` entries preserve symlink aliases and their resolved targets, including multi-link chains. Linux recreates allowed aliases hidden by the protected-region mount; macOS allows both spellings. Dangling links, cycles, and hard-denied targets remain blocked.

V2 filesystem rules support literal paths and trailing `/**` subtree notation. Other security-critical globs are rejected because Linux and macOS cannot guarantee identical behavior for them.

Policies always use version 2 semantics. The `policyVersion` field may be omitted; if present, it must be `2`. Filesystem paths must be literals or use trailing `/**` subtree notation.

## Configuration trust and grants

- Project `.pi/sandbox*.json` is used only when Pi reports the project trusted.
- Project configuration cannot disable the sandbox, request wildcard network access, or grant filesystem access outside the canonical project root.
- Session grants remain in memory.
- “Allow for this project” grants are stored under `~/.pi/agent/sandbox-projects/`, keyed by canonical project path—not in the agent-writable repository.
- Active global, project, mode, and grant policy files are write-protected from model tools and sandboxed bash.
- Policy is validated and snapshotted. It is not reread before every tool call.

Global configuration is the place for powerful controls such as `filesystem.disabled`, wildcard domains, Unix socket access, Apple Events, or weaker isolation flags. `enableWeakerNetworkIsolation` is false by default.

## Tool behavior

### Exact filesystem tools

`read`, `write`, and `edit` resolve paths against the tool's `ctx.cwd`, canonicalize existing symlinks/deepest existing ancestors, and apply hard-deny → allow → prompt precedence before execution.

### Recursive filesystem tools

Pi's built-in `grep` and `find` implementations spawn local `rg`/`fd` processes that extensions cannot currently replace through their operations interface. To avoid leaking a nested hard-denied file, `grep`, `find`, and `ls` are conservatively blocked when the requested root contains a hard-denied descendant. Use a narrower allowed root.

### Agent bash

- macOS Seatbelt can report an attributable denied read. Unknown paths may be prompted after the command fails.
- Linux bubblewrap hides/masks denied paths. Generic `ENOENT` is not treated as authorization evidence.
- Commands are never automatically retried after a grant because they may already have performed writes or other side effects.
- The agent can call `request_sandbox_access` with an explicit operation, path, and reason. The tool always requires user approval.

### User `!cmd`

`!cmd` remains sandboxed and uses Pi's cancellation-preserving execution path. It does not attempt unreliable automatic read escalation. Use:

```text
/sandbox-allow-read <path>
/sandbox-allow-write <path>
```

## Commands and modes

```text
pi --no-sandbox                     explicitly disable sandboxing for the session
pi --sandbox-mode read-only         start in a named mode
/sandbox                            show effective policy and capability details
/sandbox-mode [default|read-only|build]
/sandbox-enable
/sandbox-disable                    explicit visible bypass for the current session
/sandbox-allow-read <path>
/sandbox-allow-write <path>
```

| Mode | Read | Write | Network |
|---|---|---|---|
| `default` | policy prompt/fail-closed | policy prompt | policy prompt |
| `read-only` | policy prompt/fail-closed | deny | policy prompt |
| `build` | policy prompt/fail-closed | policy prompt | policy prompt |

Policy/runtime changes are serialized. If a refresh fails, the extension attempts to restore the previous runtime; if restoration fails, tool execution remains blocked.

## macOS strict-mode bootstrap

Strict mode must let the shell and dynamic loader start. The effective policy displays its bootstrap exceptions. Detection covers:

- `/bin`, `/usr`, `/System`, `/Library`, `/private`, `/dev`, and `/Applications`;
- Homebrew (`/opt/homebrew`, `/usr/local`);
- MacPorts (`/opt/local`);
- Nix (`/nix`, `/run`) when present;
- the active Node executable and configured shell.

These are readable compatibility exceptions, not hidden guarantees. `home` scope avoids most strict-mode bootstrap complexity.

## Security limitations

- Trusted Pi extensions and arbitrary custom tools run in the host Pi process and are not automatically confined.
- This is not a VM/container boundary; use one for hostile or unattended work.
- Directory names and limited metadata may still be observable through an allowed parent.
- An allowed network destination can still receive exfiltrated data.
- If credentials are inherited through child environment variables and no runtime credential rules are configured, bash may see them. `/sandbox` reports this posture.
- macOS Apple Events, weaker network isolation, broad Unix sockets, wildcard network access, and `filesystem.disabled` substantially weaken isolation and must be set only in trusted user configuration.

## Development and verification

```bash
npm run runtime:build
npm --prefix sandbox-runtime run typecheck
npm run ci:fmt
npm run ci:lint
npm run check
npm test
```

The root tests include:

- v2 config/trust/path-policy tests;
- macOS Seatbelt profile-order tests that run without a macOS host;
- Linux end-to-end final-deny tests when run on Linux;
- local-runtime resolution and schema tests.

The runtime's original full test suite uses Bun (`npm --prefix sandbox-runtime test`) when Bun is available.

## Acknowledgements

Based on Pi's sandbox extension example by Mario Zechner and Anthropic's Sandbox Runtime, under their respective licenses.
