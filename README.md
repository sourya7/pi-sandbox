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

## Policy version 3 and data-driven modes

The trusted default policy lives at `~/.pi/agent/sandbox.json`. Version 3 models each capability as an allow list, a hard-deny list, and an `otherwise` action:

```json
{
  "policyVersion": 3,
  "enabled": true,
  "failClosed": true,
  "network": {
    "allow": ["github.com", "*.github.com", "registry.npmjs.org"],
    "deny": [],
    "otherwise": "prompt"
  },
  "filesystem": {
    "read": {
      "scope": "home",
      "allow": ["."],
      "deny": ["~/.ssh", "~/.aws"],
      "otherwise": "prompt"
    },
    "write": {
      "allow": [".", "/tmp"],
      "deny": [".env"],
      "otherwise": "prompt"
    }
  }
}
```

Evaluation is consistent for each capability:

1. An explicit hard deny blocks the operation without prompting.
2. A resolved explicit allowance permits it without prompting.
3. `otherwise: "prompt"` requests approval when possible and otherwise fails closed.
4. `otherwise: "deny"` silently blocks an unlisted operation.

An `otherwise` deny does not erase listed allowances. This is a normal default-deny allowlist:

```json
{
  "policyVersion": 3,
  "network": {
    "allow": ["github.com", "*.github.com"],
    "deny": [],
    "otherwise": "deny"
  },
  "filesystem": {
    "read": {
      "scope": "strict",
      "allow": ["."],
      "deny": [],
      "otherwise": "prompt"
    },
    "write": {
      "allow": ["/tmp"],
      "deny": [],
      "otherwise": "deny"
    }
  }
}
```

Here GitHub and `/tmp` remain directly available, while other network destinations and writes are denied without a prompt.

### Named profiles

Every safe lowercase filename defines a mode. For example, `~/.pi/agent/sandbox.restricted.json` defines `pi --sandbox-mode restricted` without a registry or code change:

```json
{
  "policyVersion": 3,
  "network": {
    "allow": ["github.com", "*.github.com"],
    "otherwise": "deny"
  },
  "filesystem": {
    "read": {
      "allow": [],
      "otherwise": "prompt"
    },
    "write": {
      "allow": ["/tmp"],
      "otherwise": "deny"
    }
  }
}
```

The filename identifies the profile; there is no inner `mode` block. Mode names must match `^[a-z0-9][a-z0-9_-]*$`. Missing, malformed, unsafe, and custom v2 profiles fail closed rather than silently using default behavior.

The v3 base must explicitly define read, write, and network `otherwise` actions. A named profile may override an action or omit it to inherit the base action.

Global profiles use source-aware merge semantics:

| Field | Named profile behavior |
|---|---|
| `filesystem.read.allow`, `filesystem.write.allow`, `network.allow` | A present list replaces the inherited list; an omitted field inherits it. |
| `filesystem.read.deny`, `filesystem.write.deny`, `network.deny` | Union with inherited denies; a profile cannot erase a hard deny. |
| `otherwise` and `filesystem.read.scope` | A present value overrides; an omitted value inherits. |
| Other trusted global controls | Normal scalar/object override. |
| Project approvals, reactive grants, session grants | Add explicit allowances after trusted-profile resolution; hard denies still win. |

Only trusted global configuration controls `otherwise` and read scope. Project files can add restrictions and request explicit capabilities, but cannot alter fallback behavior.

### Read scopes

| Scope | Behavior |
|---|---|
| `home` | Protect the user's home directory and reopen configured paths. Paths outside home remain readable unless hard-denied. |
| `strict` | Protect filesystem root and reopen configured/runtime-bootstrap paths. Use this for a true listed-only read policy. |
| `open` | No implicit protected region; only explicit hard denies. |

`filesystem.write.allow` necessarily implies read access, except below a hard deny. Hard read denies are also protected from writes and renames so a process cannot move a secret into a readable location.

Literal read allowances preserve symlink aliases and their resolved targets, including multi-link chains. Linux recreates allowed aliases hidden by the protected-region mount; macOS allows both spellings. Dangling links, cycles, and hard-denied targets remain blocked.

V2 and v3 filesystem rules support literal paths and trailing `/**` subtree notation. Other security-critical globs are rejected because Linux and macOS cannot guarantee identical behavior for them.

### Migrating from policy version 2 or the earlier v3 draft

Version 2 remains compatible for the legacy `default`, `read-only`, and `build` modes. Custom v2 mode names do not fall back to default.

For each trusted global file:

1. Set `"policyVersion": 3`.
2. Remove the obsolete inner `mode` object.
3. Move `allowedDomains`/`deniedDomains` to `network.allow`/`network.deny` and add `network.otherwise`.
4. Move `readScope`, `allowRead`, and `denyRead` under `filesystem.read` as `scope`, `allow`, and `deny`; add `otherwise`.
5. Move `allowWrite` and `denyWrite` under `filesystem.write` as `allow` and `deny`; add `otherwise`.
6. Review named-profile allow lists: a present list replaces inherited direct allowances, while an omitted list inherits.
7. Run `/sandbox` and verify the resolved actions, per-capability sources, file states, and effective allowances.

Project declarations and user-owned reactive grants may remain version 2. Request approval records remain version 2 internal records.

## Configuration trust, project requests, and grants

Allow fields have source-dependent authority:

| Source | Meaning of allow fields |
|---|---|
| Built-in defaults and trusted global base/mode profile | Direct grant |
| Trusted project `.pi/sandbox*.json` | Request requiring user approval |
| User-owned project grant | Direct, previously approved grant |
| In-memory session allowance | Direct session grant |

A trusted project can declare reproducible access needs using the existing fields:

```json
{
  "policyVersion": 2,
  "network": {
    "allowedDomains": ["packages.example.internal"],
    "deniedDomains": []
  },
  "filesystem": {
    "allowRead": ["../shared-sdk"],
    "allowWrite": ["~/.cache/example-build"],
    "denyRead": [".env"],
    "denyWrite": [".github/workflows"]
  }
}
```

Project `allowRead`, `allowWrite`, and `allowedDomains` entries are reviewed before sandbox startup. A project may also use the v3 nested spellings (`filesystem.read.allow`, `filesystem.write.allow`, and `network.allow`). Project v3 `otherwise` and read-scope values are ignored with a warning because fallback behavior belongs to trusted global policy. Trust permits loading a declaration but does not approve it. Project deny entries apply immediately because they only restrict access. External paths are valid requests; they are not silently granted or discarded. Project wildcard domain requests and powerful controls remain rejected.

Pi does not normally treat `.pi/sandbox*.json` alone as a trust-triggering resource. When this package is loaded as a user/global or CLI extension, it participates in Pi's `project_trust` event so a sandbox-only project can be trusted explicitly. If other trust-triggering Pi resources are present, it defers to Pi's built-in trust flow.

Approved declared requests are stored in `~/.pi/agent/sandbox-projects/<project-id>[.<mode>].requests.json`, keyed by canonical project path and mode. An expanded request prompts again, while a removed request stops contributing declared access. Non-interactive sessions never auto-approve pending requests and continue with them blocked.

Reactive “Allow for this project” grants remain separate in `<project-id>[.<mode>].json`. They support dynamic or undeclared needs and remain direct user-owned grants even if a project declaration later changes.

- Project `.pi/sandbox*.json` is used only when Pi reports the project trusted.
- Session grants remain in memory.
- Active global, project, mode, reactive-grant, and request-approval files are write-protected from model tools and sandboxed bash.
- `/sandbox` reports project requests, their sources and statuses, declared approvals, and reactive grants separately.
- Policy is validated and snapshotted. It is not reread before every tool call.

Global configuration is the place for powerful controls such as `filesystem.disabled`, wildcard domains, Unix socket access, Apple Events, or weaker isolation flags. `enableWeakerNetworkIsolation` is false by default. Global hard denies remain authoritative over every project approval; no global delegation setting is required.

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

These commands always require a separate operator confirmation. In TUI mode Pi displays it directly; in RPC mode it emits an `extension_ui_request` with `method: "confirm"` for the trusted client (for example Emacs) to display and answer. JSON and print modes cannot authorize grants. The agent-facing `request_sandbox_access` tool cannot remove hard denies or initiate an exact-deny override.

When the requested canonical path exactly matches a configured `denyRead` or `denyWrite` root, confirmation creates an in-memory override for the active mode and session: Pi derives an effective policy with only that exact rule removed and adds the path as a session allowance. Nested exceptions are intentionally rejected—for example, `~/.ssh/known_hosts` cannot be reopened beneath `denyRead: ["~/.ssh"]`—because removing the broader rule would expose more than requested. Credential rules, policy/control files, and Sandbox Runtime mandatory write protections remain non-overridable. Use trusted user policy or `/sandbox-disable` explicitly when exact-match semantics are insufficient.

## Commands and modes

```text
pi --no-sandbox                     explicitly disable sandboxing for the session
pi --sandbox-mode restricted        start in a named global mode profile
/sandbox                            show effective policy, sources, and capabilities
/sandbox-mode [name]                show or switch mode; completion discovers global profiles
/sandbox-enable
/sandbox-disable                    explicit visible bypass for the current session
/sandbox-allow-read <path>          operator-confirmed session grant/exact deny override
/sandbox-allow-write <path>         operator-confirmed session grant/exact deny override
/sandbox-clear-overrides            clear exact deny overrides for the active mode
```

`otherwise: "prompt"` enables escalation for an operation that has no matching allow or deny rule. `otherwise: "deny"` silently denies only unlisted operations; explicit profile allowances and approved grants remain active. Version 3 permits arbitrary named profiles rather than a fixed mode table.

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

- v2 compatibility and v3 data-driven mode/config/trust/path-policy tests;
- macOS Seatbelt profile-order tests that run without a macOS host;
- Linux end-to-end final-deny tests when run on Linux;
- local-runtime resolution and schema tests.

The runtime's original full test suite uses Bun (`npm --prefix sandbox-runtime test`) when Bun is available.

## Acknowledgements

Based on Pi's sandbox extension example by Mario Zechner and Anthropic's Sandbox Runtime, under their respective licenses.
