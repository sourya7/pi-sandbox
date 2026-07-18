# pi-sandbox

Sandbox for [pi](https://pi.dev/).

Sandboxes pi like this:
- read/write/edit: direct control using allow/deny lists
- bash: uses [`@anthropic-ai/sandbox-runtime`](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime) to control network and file system access

When a blocked action is attempted, the user is
prompted to allow it temporarily or permanently rather than silently failing.

![demo](./demo/demo.gif)

## Notes
There is an example config at [sandbox.json](./sandbox.json). It was quite a few things added to get this extension to work with [agent-browser](https://agent-browser.dev/) and other common tools.

These open significant security loopholes, so shouldn't be used in a sensitive context or when you don't need browser support.

You may need to trial and error to find additional things you need to allow.

## Quickstart

#### Prerequisites

`pi-sandbox` delegates the OS-level bash sandbox to
[`@anthropic-ai/sandbox-runtime`](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime),
published from Anthropic's
[`anthropic-experimental/sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime).
The sandbox runtime checks for [`ripgrep`](https://github.com/BurntSushi/ripgrep) (the
`rg` binary) on **both macOS and Linux** at sandbox-init time. If `rg`
is not on the `PATH` that pi was launched with, sandbox initialization
fails with:

```
Sandbox initialization failed: Sandbox dependencies not available: ripgrep (rg) not found
```

Install ripgrep before enabling the extension:

| Platform | Install |
|---|---|
| macOS (Homebrew) | `brew install ripgrep` |
| macOS (MacPorts) | `sudo port install ripgrep` |
| Linux (Debian/Ubuntu) | `sudo apt install ripgrep` |
| Linux (Fedora/RHEL) | `sudo dnf install ripgrep` |
| Linux (Arch) | `sudo pacman -S ripgrep` |
| From source / other | <https://github.com/BurntSushi/ripgrep#installation> |

If `which rg` succeeds in your shell but pi still reports `rg not
found`, pi is being launched from a parent process whose `PATH` does
not include the directory containing `rg` (common when GUI launchers
inherit a minimal non-login `PATH`). On macOS, `/opt/homebrew/bin` and
`/usr/local/bin` are the usual culprits — make sure your launcher's
environment includes whichever one your install uses.

#### Install
```bash
pi install npm:pi-sandbox
```

#### Configure
Add a config like this either to `~/.pi/agent/sandbox.json` (global) or to `.pi/sandbox.json` (local).
Global config acts as a baseline and local config extends it. Known sandbox arrays (`allowedDomains`, `deniedDomains`, `allowRead`, `denyRead`, `allowWrite`, `denyWrite`) are merged additively with de-duplication; scalar/object fields still use normal override semantics.

Deny rules always take precedence over allow rules.

```json
{
  "enabled": true,
  "network": {
    "allowLocalBinding": true,     // ditto
    "allowAllUnixSockets": true,   // ditto
    "allowedDomains": ["github.com", "*.github.com"],
    "deniedDomains": []
  },
  "filesystem": {
    // For READS:
    // - ANY read is prompted unless the path is already in allowRead
    // - DENY takes precedence and is never prompted
    "denyRead": ["/Users", "/home"],
    "allowRead": [".", "~/.config", "~/.local", "Library"],

    // For WRITES:
    // - empty ALLOW means no write access at all
    // - DENY takes precedence and is never prompted
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".env", ".env.*", "*.pem", "*.key"]
  }
}
```

#### Usage

```
pi --no-sandbox                    disable sandboxing for the session
pi --sandbox-mode read-only         start in a named sandbox mode
/sandbox                           show current configuration and session allowances
/sandbox-mode                      show active sandbox mode
/sandbox-mode read-only            switch to read-only mode
/sandbox-mode build                switch to build mode
/sandbox-mode default              switch to default mode
```

## What it does

**Bash commands** are wrapped with `sandbox-exec` (macOS) or `bubblewrap`
(Linux) to enforce network and filesystem restrictions at the OS level.

**Read, write, and edit tool calls** are intercepted before execution and
checked against the same filesystem policy. The OS-level sandbox cannot cover
these tools because they run directly in the Node.js process rather than in a
subprocess.

When a block is triggered, a prompt appears with four options:

- Abort (keep blocked)
- Allow for this session only
- Allow for this project — written to `.pi/sandbox.json` or `.pi/sandbox.<mode>.json`
- Allow for all projects — written to `~/.pi/agent/sandbox.json` or `~/.pi/agent/sandbox.<mode>.json`

**Session allowances** are held in memory only. They are never written to disk
and the agent has no way to read or modify them. They are mode-local, so a grant
in `build` does not leak into `read-only`. They are reset when the extension
reloads or pi restarts.

### Sandbox modes

The active mode selects additional mode-specific config files and a mode policy:

| Mode | Read | Write | Network |
|------|------|-------|---------|
| `default` | Prompt unknown reads | Prompt unknown writes | Prompt unknown domains |
| `read-only` | Prompt unknown reads | Deny writes without prompting | Prompt unknown domains |
| `build` | Prompt unknown reads | Prompt unknown writes | Prompt unknown domains |

Config merge order for `default`:

```text
DEFAULT_CONFIG -> ~/.pi/agent/sandbox.json -> <project>/.pi/sandbox.json -> session allowances
```

Config merge order for named modes such as `read-only` or `build`:

```text
DEFAULT_CONFIG
-> ~/.pi/agent/sandbox.json
-> ~/.pi/agent/sandbox.<mode>.json
-> <project>/.pi/sandbox.json
-> <project>/.pi/sandbox.<mode>.json
-> session allowances for that mode
```

Read-only mode prevents the model from writing through write/edit/bash and disables write escalation prompts. It still permits network research according to `network.allowedDomains` and prompts for unknown domains. Trusted extensions may perform their own internal writes, such as pi-web-access cloning GitHub repos to `/tmp/pi-github-repos`; this is outside the direct model tool surface and should be configured separately if needed.

### What is prompted vs. hard-blocked

| Rule | Behaviour |
|------|-----------|
| Domain not in `allowedDomains` | Prompted (bash and `!cmd`) |
| Path not in `allowRead` | Prompted (read tool); granting adds to `allowRead` |
| Path not in `allowWrite` | Prompted (write/edit tools and bash write failures) |
| Path in `denyRead` | Hard-blocked, no prompt |
| Path in `denyWrite` | Hard-blocked, no prompt |
| Domain in `deniedDomains` | Hard-blocked at OS level, no prompt |

If a path is added to `allowWrite` via a prompt but is also present in
`denyWrite`, it remains blocked. A warning is shown explaining which config
files to check.

`allowedDomains` supports `*.example.com` wildcards. It also supports `"*"` to
allow all domains; pi-sandbox shows a warning when this is configured because it
removes per-domain prompts and can be easy to add accidentally. `allowWrite` uses prefix
matching, so `.` covers the entire current working directory.

> **⚠️ Deny rules always win:** `denyRead` and `denyWrite` take precedence over
> matching allow rules and are never prompted.

If neither file exists, built-in defaults apply (see above for the defaults).

The footer shows a lock indicator while the sandbox is active.

## Ackowledgements
Based on code from
[badlogic/pi-mono](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/examples/extensions/sandbox/index.ts)
by Mario Zechner, used under the
[MIT License](https://github.com/badlogic/pi-mono/blob/main/LICENSE).
