import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { type AgentToolResult, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
  createBashToolDefinition,
  isToolCallEventType,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";

import {
  addDomainToConfig,
  addReadPathToConfig,
  addWritePathToConfig,
  getConfigPaths,
  loadConfig,
} from "./config.ts";
import { DEFAULT_MODE, getModePolicy } from "./modes.ts";
import {
  canonicalizePath,
  domainIsAllowed,
  extractDomainsFromCommand,
  matchesPattern,
  shouldPromptForWrite,
} from "./policy.ts";
import {
  buildRuntimeConfig,
  createSandboxedBashOps,
  extractSandboxViolation,
  initializeSandbox,
  reinitializeSandbox,
  type SessionAllowances,
  supportsNodeEnvProxy,
} from "./sandbox-runtime.ts";
import {
  formatSandboxConfiguration,
  formatSandboxStatus,
  type PermissionChoice,
  promptDomainBlock,
  promptReadBlock,
  promptWriteBlock,
  warnIfAllDomainsAllowed,
} from "./ui.ts";

function newAllowances(): SessionAllowances {
  return { domains: [], readPaths: [], writePaths: [] };
}

function commandArgText(args: unknown): string {
  if (typeof args === "string") return args.trim();
  if (Array.isArray(args)) return args.join(" ").trim();
  if (args && typeof args === "object" && "args" in args) return commandArgText(args.args);
  return "";
}

export default function (pi: ExtensionAPI) {
  pi.registerFlag("no-sandbox", {
    description: "Disable OS-level sandboxing for bash commands",
    type: "boolean",
    default: false,
  });

  pi.registerFlag("sandbox-mode", {
    description: "Sandbox mode to use, e.g. default, read-only, build",
    type: "string",
    default: DEFAULT_MODE,
  });

  const localCwd = process.cwd();
  const userShellPath = SettingsManager.create(localCwd).getShellPath();
  const localBash = createBashToolDefinition(localCwd, { shellPath: userShellPath });

  let sandboxEnabled = false;
  let sandboxInitialized = false;
  let activeMode = DEFAULT_MODE;
  const allowancesByMode = new Map<string, SessionAllowances>();
  const pendingDomainPrompts = new Map<string, Promise<boolean>>();
  let activeCtx: Parameters<typeof warnIfAllDomainsAllowed>[0] | undefined;
  let activeToolCtx: Parameters<typeof warnIfAllDomainsAllowed>[0] | undefined;
  let activeToolRunId = 0;

  function getModeAllowances(mode = activeMode): SessionAllowances {
    let allowances = allowancesByMode.get(mode);
    if (!allowances) {
      allowances = newAllowances();
      allowancesByMode.set(mode, allowances);
    }
    return allowances;
  }

  const effectiveDomains = (cwd: string) => [
    ...(loadConfig(cwd, activeMode).network?.allowedDomains ?? []),
    ...getModeAllowances().domains,
  ];
  const effectiveReadPaths = (cwd: string) => [
    ...(loadConfig(cwd, activeMode).filesystem?.allowRead ?? []),
    ...getModeAllowances().readPaths,
  ];
  const effectiveWritePaths = (cwd: string) => [
    ...(getModePolicy(activeMode).write === "deny"
      ? []
      : (loadConfig(cwd, activeMode).filesystem?.allowWrite ?? [])),
    ...(getModePolicy(activeMode).write === "deny" ? [] : getModeAllowances().writePaths),
  ];

  function runtimeConfigForActiveMode(cwd: string): ReturnType<typeof loadConfig> {
    const config = loadConfig(cwd, activeMode);
    if (getModePolicy(activeMode).write !== "deny") return config;
    return {
      ...config,
      filesystem: {
        ...config.filesystem,
        allowWrite: [],
      },
    };
  }

  function runtimeAllowancesForActiveMode(): SessionAllowances {
    const allowances = getModeAllowances();
    if (getModePolicy(activeMode).write !== "deny") return allowances;
    return { ...allowances, writePaths: [] };
  }

  async function refreshSandbox(cwd: string): Promise<void> {
    if (!sandboxInitialized) return;
    try {
      await reinitializeSandbox(
        runtimeConfigForActiveMode(cwd),
        runtimeAllowancesForActiveMode(),
        cwd,
        (host) => handleRuntimeBlockedDomain(host, cwd),
      );
    } catch (error) {
      console.error(`Warning: Failed to reinitialize sandbox: ${error}`);
    }
  }

  async function applyChoice(
    choice: Exclude<PermissionChoice, "abort">,
    kind: "domain" | "read" | "write",
    value: string,
    cwd: string,
    refresh = true,
  ): Promise<void> {
    const paths = getConfigPaths(cwd, activeMode);
    const target =
      choice === "project"
        ? (paths.projectModePath ?? paths.projectBasePath)
        : (paths.globalModePath ?? paths.globalBasePath);
    const allowances = getModeAllowances();

    if (kind === "domain") {
      if (!allowances.domains.includes(value)) allowances.domains.push(value);
      if (choice !== "session") addDomainToConfig(target, value);
    } else if (kind === "read") {
      if (!allowances.readPaths.includes(value)) allowances.readPaths.push(value);
      if (choice !== "session") addReadPathToConfig(target, value);
    } else {
      if (!allowances.writePaths.includes(value)) allowances.writePaths.push(value);
      if (choice !== "session") addWritePathToConfig(target, value);
    }
    if (refresh) await refreshSandbox(cwd);
  }

  async function handleRuntimeBlockedDomain(host: string, cwd: string): Promise<boolean> {
    if (domainIsAllowed(host, effectiveDomains(cwd))) return true;
    const existing = pendingDomainPrompts.get(host);
    if (existing) return existing;

    const prompt = (async () => {
      const policy = getModePolicy(activeMode);
      if (policy.network === "deny") return false;
      const ctxToUse = activeToolCtx ?? activeCtx;
      if (!ctxToUse) return false;
      const promptCwd = ctxToUse.cwd ?? cwd;
      const choice = await promptDomainBlock(ctxToUse, host);
      if (choice === "abort") return false;
      await applyChoice(choice, "domain", host, promptCwd, false);
      SandboxManager.updateConfig(
        buildRuntimeConfig(
          runtimeConfigForActiveMode(promptCwd),
          runtimeAllowancesForActiveMode(),
          promptCwd,
        ),
      );
      return true;
    })().finally(() => pendingDomainPrompts.delete(host));

    pendingDomainPrompts.set(host, prompt);
    return prompt;
  }

  function updateStatus(
    ctx: Parameters<typeof warnIfAllDomainsAllowed>[0],
    config: ReturnType<typeof loadConfig>,
  ) {
    ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("accent", formatSandboxStatus(config, activeMode)));
  }

  async function enableSandbox(
    ctx: Parameters<typeof warnIfAllDomainsAllowed>[0],
    setProxyEnvironment: boolean,
  ): Promise<boolean> {
    activeCtx = ctx;
    const config = loadConfig(ctx.cwd, activeMode);
    const runtimeConfig = runtimeConfigForActiveMode(ctx.cwd);
    const platform = process.platform;
    if (platform !== "darwin" && platform !== "linux") {
      ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
      return false;
    }

    try {
      await initializeSandbox(runtimeConfig, runtimeAllowancesForActiveMode(), ctx.cwd, (host) =>
        handleRuntimeBlockedDomain(host, ctx.cwd),
      );
      if (setProxyEnvironment && supportsNodeEnvProxy(process.versions.node)) {
        process.env.NODE_USE_ENV_PROXY ??= "1";
      }
      sandboxEnabled = true;
      sandboxInitialized = true;
      warnIfAllDomainsAllowed(ctx, config);
      updateStatus(ctx, config);
      return true;
    } catch (error) {
      sandboxEnabled = false;
      ctx.ui.notify(
        `Sandbox initialization failed: ${error instanceof Error ? error.message : error}`,
        "error",
      );
      return false;
    }
  }

  pi.registerTool({
    ...localBash,
    label: "bash (sandboxed)",
    async execute(id, params, signal, onUpdate, ctx) {
      const runBash = async () => {
        const runId = ++activeToolRunId;
        activeToolCtx = ctx;
        try {
          if (!sandboxEnabled || !sandboxInitialized) {
            return await localBash.execute(id, params, signal, onUpdate, ctx);
          }
          return await createBashToolDefinition(localCwd, {
            operations: createSandboxedBashOps(userShellPath),
            shellPath: userShellPath,
          }).execute(id, params, signal, onUpdate, ctx);
        } finally {
          if (activeToolRunId === runId) activeToolCtx = undefined;
        }
      };

      let result: AgentToolResult<any>;
      try {
        result = await runBash();
      } catch (error) {
        if (!(error instanceof Error) || !extractSandboxViolation(error.message)) {
          throw error;
        }
        result = {
          content: [
            {
              type: "text",
              text: `Error: Command failed with OS-level sandbox restriction: ${error.message}`,
            },
          ],
          details: {},
        };
      }

      if (sandboxEnabled && sandboxInitialized) {
        const output = result.content
          .filter((content: any) => content.type === "text")
          .map((content: any) => content.text)
          .join("\n");
        const violation = extractSandboxViolation(output);

        if (violation?.type === "read") {
          const policy = getModePolicy(activeMode);
          if (policy.read === "deny") {
            return {
              content: [
                {
                  type: "text",
                  text:
                    `Blocked by sandbox mode "${activeMode}": reads are not permitted.\n` +
                    `Attempted read path: ${violation.path}`,
                },
              ],
              details: {},
            };
          }

          const choice = await promptReadBlock(ctx, violation.path);
          if (choice !== "abort") {
            await applyChoice(choice, "read", violation.path, ctx.cwd);
            onUpdate?.({
              content: [
                {
                  type: "text",
                  text: `\n--- Read access granted for "${violation.path}", retrying ---\n`,
                },
              ],
              details: {},
            });
            return runBash();
          }
        }

        if (violation?.type === "write") {
          const blockedPath = violation.path;
          const policy = getModePolicy(activeMode);
          if (policy.write === "deny") {
            return {
              content: [
                {
                  type: "text",
                  text:
                    `Blocked by sandbox mode "${activeMode}": writes are not permitted.\n` +
                    `Attempted write path: ${blockedPath}\n` +
                    `Ask the user to switch to "build" mode if file changes are required.`,
                },
              ],
              details: {},
            };
          }

          const choice = await promptWriteBlock(ctx, blockedPath);
          if (choice !== "abort") {
            await applyChoice(choice, "write", blockedPath, ctx.cwd);
            const config = loadConfig(ctx.cwd, activeMode);
            const paths = getConfigPaths(ctx.cwd, activeMode);
            if (matchesPattern(blockedPath, config.filesystem?.denyWrite ?? [])) {
              ctx.ui.notify(
                `⚠️ "${blockedPath}" was added to allowWrite, but it is also in denyWrite and will remain blocked.\n` +
                  `Check denyWrite in:\n  ${paths.projectModePath ?? paths.projectBasePath}\n  ${paths.globalModePath ?? paths.globalBasePath}`,
                "warning",
              );
              return result;
            }
            onUpdate?.({
              content: [
                {
                  type: "text",
                  text: `\n--- Write access granted for "${blockedPath}", retrying ---\n`,
                },
              ],
              details: {},
            });
            return runBash();
          }
        }

        if (violation?.type === "network") {
          return {
            content: [
              {
                type: "text",
                text: `Blocked by sandbox network policy: ${violation.host ?? violation.raw}`,
              },
            ],
            details: {},
          };
        }
      }
      return result;
    },
  });

  pi.on("user_bash", async (event, ctx) => {
    if (!sandboxEnabled || !sandboxInitialized) return;

    for (const domain of extractDomainsFromCommand(event.command)) {
      if (!domainIsAllowed(domain, effectiveDomains(ctx.cwd))) {
        const policy = getModePolicy(activeMode);
        if (policy.network === "deny") {
          return {
            result: {
              output: `Sandbox mode "${activeMode}" blocks network access to "${domain}".`,
              exitCode: 1,
              cancelled: false,
              truncated: false,
            },
          };
        }
        const choice = await promptDomainBlock(ctx, domain);
        if (choice === "abort") {
          return {
            result: {
              output: `Blocked: "${domain}" is not in allowedDomains. Use /sandbox to review your config.`,
              exitCode: 1,
              cancelled: false,
              truncated: false,
            },
          };
        }
        await applyChoice(choice, "domain", domain, ctx.cwd);
      }
    }
    return { operations: createSandboxedBashOps(userShellPath) };
  });

  pi.on("tool_call", async (event, ctx) => {
    if (!sandboxEnabled) return;
    const config = loadConfig(ctx.cwd, activeMode);
    if (!config.enabled) return;
    const paths = getConfigPaths(ctx.cwd, activeMode);
    const projectPath = paths.projectModePath ?? paths.projectBasePath;
    const globalPath = paths.globalModePath ?? paths.globalBasePath;

    if (sandboxInitialized && isToolCallEventType("bash", event)) {
      for (const domain of extractDomainsFromCommand(event.input.command)) {
        if (!domainIsAllowed(domain, effectiveDomains(ctx.cwd))) {
          const policy = getModePolicy(activeMode);
          if (policy.network === "deny") {
            return {
              block: true,
              reason: `Sandbox mode "${activeMode}" blocks network access to "${domain}".`,
            };
          }
          const choice = await promptDomainBlock(ctx, domain);
          if (choice === "abort") {
            return {
              block: true,
              reason: `Network access to "${domain}" is blocked (not in allowedDomains).`,
            };
          }
          await applyChoice(choice, "domain", domain, ctx.cwd);
        }
      }
    }

    if (isToolCallEventType("read", event)) {
      const path = canonicalizePath(event.input.path);
      const denyRead = config.filesystem?.denyRead ?? [];
      if (matchesPattern(path, denyRead)) {
        return {
          block: true,
          reason:
            `Sandbox: read access denied for "${path}" (in denyRead). ` +
            `To change this, edit denyRead in:\n  ${projectPath}\n  ${globalPath}`,
        };
      }
      if (!matchesPattern(path, effectiveReadPaths(ctx.cwd))) {
        const policy = getModePolicy(activeMode);
        if (policy.read === "deny") {
          return {
            block: true,
            reason: `Sandbox mode "${activeMode}" blocks read access to "${path}".`,
          };
        }
        const choice = await promptReadBlock(ctx, path);
        if (choice === "abort") {
          return { block: true, reason: `Sandbox: read access denied for "${path}"` };
        }
        await applyChoice(choice, "read", path, ctx.cwd);
        return;
      }
    }

    if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
      const path = canonicalizePath((event.input as { path: string }).path);
      const denyWrite = config.filesystem?.denyWrite ?? [];
      if (matchesPattern(path, denyWrite)) {
        return {
          block: true,
          reason:
            `Sandbox: write access denied for "${path}" (in denyWrite). ` +
            `To change this, edit denyWrite in:\n  ${projectPath}\n  ${globalPath}`,
        };
      }
      const policy = getModePolicy(activeMode);
      if (policy.write === "deny") {
        return {
          block: true,
          reason:
            `Sandbox mode "${activeMode}" does not permit writes to "${path}". ` +
            `Current mode allows research and inspection only. Ask the user to switch to "build" mode if file changes are required.`,
        };
      }
      if (shouldPromptForWrite(path, effectiveWritePaths(ctx.cwd), matchesPattern)) {
        const choice = await promptWriteBlock(ctx, path);
        if (choice === "abort") {
          return {
            block: true,
            reason: `Sandbox: write access denied for "${path}" (not in allowWrite)`,
          };
        }
        await applyChoice(choice, "write", path, ctx.cwd);
        return;
      }
    }
  });

  pi.on("session_start", async (_event, ctx) => {
    activeMode =
      ((pi.getFlag("sandbox-mode") as string | undefined) || DEFAULT_MODE).trim() || DEFAULT_MODE;
    if (pi.getFlag("no-sandbox") as boolean) {
      sandboxEnabled = false;
      ctx.ui.notify("Sandbox disabled via --no-sandbox", "warning");
      return;
    }
    if (!loadConfig(ctx.cwd, activeMode).enabled) {
      sandboxEnabled = false;
      ctx.ui.notify("Sandbox disabled via config", "info");
      return;
    }
    await enableSandbox(ctx, true);
  });

  pi.on("session_shutdown", async () => {
    if (!sandboxInitialized) return;
    try {
      await SandboxManager.reset();
    } catch {
      // Ignore cleanup errors.
    }
  });

  pi.registerCommand("sandbox-enable", {
    description: "Enable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (sandboxEnabled) {
        ctx.ui.notify("Sandbox is already enabled", "info");
        return;
      }
      if (await enableSandbox(ctx, false)) ctx.ui.notify("Sandbox enabled", "info");
    },
  });

  pi.registerCommand("sandbox-disable", {
    description: "Disable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (!sandboxEnabled) {
        ctx.ui.notify("Sandbox is already disabled", "info");
        return;
      }
      if (sandboxInitialized) {
        try {
          await SandboxManager.reset();
        } catch {
          // Ignore cleanup errors.
        }
      }
      sandboxEnabled = false;
      sandboxInitialized = false;
      ctx.ui.setStatus("sandbox", "");
      ctx.ui.notify("Sandbox disabled", "info");
    },
  });

  pi.registerCommand("sandbox-mode", {
    description: "Show or switch sandbox mode",
    handler: async (args, ctx) => {
      const requestedMode = commandArgText(args);
      if (!requestedMode) {
        ctx.ui.notify(`Active sandbox mode: ${activeMode}`, "info");
        return;
      }

      activeMode = requestedMode;
      const config = loadConfig(ctx.cwd, activeMode);
      if (sandboxEnabled && config.enabled) {
        if (sandboxInitialized) await refreshSandbox(ctx.cwd);
        else await enableSandbox(ctx, false);
        updateStatus(ctx, config);
      } else if (!config.enabled) {
        ctx.ui.notify(`Sandbox config is disabled for mode "${activeMode}"`, "warning");
      }
      ctx.ui.notify(`Sandbox mode switched to "${activeMode}"`, "info");
    },
  });

  pi.registerCommand("sandbox", {
    description: "Show sandbox configuration",
    handler: async (_args, ctx) => {
      if (!sandboxEnabled) {
        ctx.ui.notify("Sandbox is disabled", "info");
        return;
      }
      ctx.ui.notify(
        formatSandboxConfiguration(
          loadConfig(ctx.cwd, activeMode),
          getConfigPaths(ctx.cwd, activeMode),
          getModeAllowances(),
          activeMode,
        ),
        "info",
      );
    },
  });
}
