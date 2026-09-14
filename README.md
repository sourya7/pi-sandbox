# pi-sandbox

OS-level sandboxing and explicit filesystem/network permissions for [Pi](https://pi.dev/).

The extension covers model-facing `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls`. Bash subprocesses use the published [Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime) with Seatbelt (`sandbox-exec`) on macOS and bubblewrap on Linux.

The responsibility boundary is intentional: this extension owns Pi integration, trusted policy, project approvals, prompts, hard-deny classification, and fail-closed lifecycle behavior. Sandbox Runtime owns OS profiles, mounts, proxies, DNS/address checks, native helpers, and violation observation.

## Local setup

```bash
git clone <this-repository>
cd pi-sandbox
npm install
pi -e .
```

The runtime is pinned to an exact reviewed release in `package.json`. Verify that it resolves from the installed registry package with:

```bash
node -e "console.log(import.meta.resolve('@anthropic-ai/sandbox-runtime'))"
```

The result should point under `node_modules/@anthropic-ai/sandbox-runtime/dist/`. No submodule checkout or local runtime build is required.

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

### Packaged native helpers

The published runtime includes executable x64/arm64 Linux `apply-seccomp` helpers, Windows helper binaries, and its JVM proxy-agent JAR. Bun, gcc, and libseccomp development headers are not needed to install this extension.

On Linux, `apply-seccomp` blocks sandboxed commands from creating Unix-domain sockets when `network.allowAllUnixSockets` is false. This protects host capabilities such as Docker, SSH/GPG agents, browser sockets, and local daemons. Unsupported architectures can set `allowAllUnixSockets: true`, but that is a significant weakening. macOS uses Seatbelt instead of `apply-seccomp`.

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

`.env` is not an unconditional built-in write deny. Add it to `filesystem.write.deny` (v3) or `filesystem.denyWrite` (v2) when the file exists and the policy should protect it. On Linux, the pinned runtime cannot safely construct a deny mount for an absent explicit deny beneath an effective writable path. Sandbox initialization therefore fails with an actionable error instead of silently dropping the deny or repeatedly failing inside bubblewrap. Create the target before startup, narrow the write allowlist, or remove the deny. A narrow write allowlist that does not cover the absent target makes the deny redundant and avoids this limitation.

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

### Network ports, IPv6, and resolved-address guards

Network allow/deny entries accept optional ports, for example `github.com:443`, `*.example.com:8443`, and the deny-only pattern `*:22`. IPv6 literals must use brackets in domain lists: `[::1]` or `[2001:db8::1]:443`.

Trusted global policies may set `network.deniedDomainReasons` to explain a denial and `network.deniedResolvedAddresses` to prevent allowed hostnames from resolving into sensitive ranges. The runtime always protects loopback, link-local, metadata endpoints, and host-interface addresses. To additionally block private/LAN ranges, configure:

```json
"deniedResolvedAddresses": [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "100.64.0.0/10",
  "fc00::/7"
]
```

Private ranges are not denied by default because explicitly allowed intranet hosts are a supported workflow. Project policies may add resolved-address denies but cannot remove trusted global denies or provide model-facing denial reasons.

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
- Existing active global, project, mode, reactive-grant, and request-approval files are write-protected from model tools and sandboxed bash.
- Every logical policy/control path, including an absent one, remains write-protected and non-overridable through Pi's exact `write` and `edit` tools.
- On Linux, an absent policy file is protected in Bash by its existing immediate policy directory. If both the project policy and `.pi/` are absent, there is no narrow mount point, so Bash may create `.pi/sandbox.json`. It cannot change the active policy snapshot or directly grant future capabilities: project allows still require approval, project fallback controls are ignored, project hard denies can only restrict access, and malformed policy fails closed on the next load. This is a future-session integrity/availability limitation, not a live-session capability escalation.
- `/sandbox` reports project requests, their sources and statuses, declared approvals, reactive grants, complete logical policy protection, runtime-protected paths, and deferred absent policy paths separately.
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

- Anthropic Sandbox Runtime currently exposes a process-global `SandboxManager`. Concurrent Pi extension instances, including parent/subagent sessions in one process, are not independently isolated and can replace or reset shared runtime state. Robust per-session isolation requires an upstream manager-instance API or a separate runtime broker process.
- Trusted Pi extensions and arbitrary custom tools run in the host Pi process and are not automatically confined.
- This is not a VM/container boundary; use one for hostile or unattended work.
- Directory names and limited metadata may still be observable through an allowed parent.
- An allowed network destination can still receive exfiltrated data.
- If credentials are inherited through child environment variables and no runtime credential rules are configured, bash may see them. `/sandbox` reports this posture.
- macOS Apple Events, weaker network isolation, broad Unix sockets, wildcard network access, and `filesystem.disabled` substantially weaken isolation and must be set only in trusted user configuration.

## Development and verification

```bash
npm run ci:fmt
npm run ci:lint
npm run check
npm test
```

The root tests include v2/v3 policy, config trust, project approvals, fail-closed lifecycle, public runtime contract, and Linux end-to-end hard-deny coverage. macOS end-to-end checks require a macOS host.

### Runtime upgrade checklist

1. Read the Sandbox Runtime release notes and security-relevant source changes.
2. Update the exact dependency version and lockfile; do not use a caret range.
3. Verify the packaged seccomp helpers and JVM agent.
4. Run formatting, lint, type-checking, and all tests on Linux and macOS.
5. Review runtime schema changes for trusted/project authority implications.
6. Publish only after hard-deny and fail-closed tests pass.

## Acknowledgements

Based on Pi's sandbox extension example by Mario Zechner and [Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime), under their respective licenses.
