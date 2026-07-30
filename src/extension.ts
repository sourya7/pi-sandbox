import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";

import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import {
  CONFIG_DIR_NAME,
  type AgentToolResult,
  type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import {
  createBashToolDefinition,
  isToolCallEventType,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

import {
  approvedSelectionFromState,
  classifyProjectAccessRequests,
  declaredProjectAllowances,
  pendingProjectRequestCount,
  type ProjectRequestSelection,
  type ProjectRequestState,
} from "./access-requests.ts";
import {
  addDomainToConfig,
  addReadPathToConfig,
  addWritePathToConfig,
  loadPolicy,
  type LoadedSandboxPolicy,
  writeProjectRequestApproval,
} from "./config.ts";
import { DEFAULT_MODE, getModePolicy } from "./modes.ts";
import {
  canonicalizePath,
  domainIsAllowed,
  evaluateReadPolicy,
  hardDeniesWithin,
  matchesPattern,
  resolvePolicyPatterns,
} from "./policy.ts";
import {
  buildRuntimeConfig,
  createSandboxedBashOps,
  extractSandboxViolation,
  getRuntimeBootstrapReadPaths,
  initializeSandbox,
  type SessionAllowances,
  supportsNodeEnvProxy,
} from "./sandbox-runtime.ts";
import {
  formatSandboxConfiguration,
  formatSandboxStatus,
  type PermissionChoice,
  promptAccessRequest,
  promptDomainBlock,
  promptProjectAccessRequests,
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

function textResult(text: string): AgentToolResult<Record<string, never>> {
  return { content: [{ type: "text", text }], details: {} };
}

type SandboxState = "disabled-by-user" | "initializing" | "active" | "failed";
type GrantKind = "domain" | "read" | "write";

export function hasProjectSandboxDeclaration(cwd: string): boolean {
  const configDirectory = join(cwd, CONFIG_DIR_NAME);
  if (!existsSync(configDirectory)) return false;
  try {
    return readdirSync(configDirectory).some((name) => /^sandbox(?:\..+)?\.json$/.test(name));
  } catch {
    return false;
  }
}

export function hasOtherProjectTrustResources(cwd: string): boolean {
  const configDirectory = join(cwd, CONFIG_DIR_NAME);
  const localResources = [
    "settings.json",
    "extensions",
    "skills",
    "prompts",
    "themes",
    "SYSTEM.md",
    "APPEND_SYSTEM.md",
  ];
  if (localResources.some((name) => existsSync(join(configDirectory, name)))) return true;

  let current = cwd;
  while (true) {
    if (existsSync(join(current, ".agents", "skills"))) return true;
    const parent = dirname(current);
    if (parent === current) return false;
    current = parent;
  }
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

  pi.on("project_trust", async (event, ctx) => {
    if (
      !hasProjectSandboxDeclaration(event.cwd) ||
      hasOtherProjectTrustResources(event.cwd) ||
      !ctx.hasUI
    ) {
      return { trusted: "undecided" };
    }
    const choice = await ctx.ui.select(
      `This project declares sandbox restrictions and access requests. Trust permits loading the declaration; it does not approve requested access.\n\n${event.cwd}`,
      ["Trust and remember", "Trust for this process", "Do not trust and remember", "Cancel"],
    );
    if (choice === "Trust and remember") return { trusted: "yes", remember: true };
    if (choice === "Trust for this process") return { trusted: "yes" };
    if (choice === "Do not trust and remember") return { trusted: "no", remember: true };
    return { trusted: "undecided" };
  });

  const localCwd = process.cwd();
  const userShellPath = SettingsManager.create(localCwd).getShellPath();
  const bootstrapShellPaths = userShellPath ? [userShellPath] : [];
  const localBash = createBashToolDefinition(localCwd, { shellPath: userShellPath });

  let state: SandboxState = "initializing";
  let activeMode = DEFAULT_MODE;
  let policy: LoadedSandboxPolicy | undefined;
  let projectRequestState: ProjectRequestState | undefined;
  const allowancesByMode = new Map<string, SessionAllowances>();
  const pendingDomainPrompts = new Map<string, Promise<boolean>>();
  let activeCtx: Parameters<typeof warnIfAllDomainsAllowed>[0] | undefined;
  let activeToolCtx: Parameters<typeof warnIfAllDomainsAllowed>[0] | undefined;
  let mutationTail: Promise<void> = Promise.resolve();
  let bashTail: Promise<void> = Promise.resolve();

  function serialize<T>(operation: () => Promise<T>): Promise<T> {
    const run = mutationTail.then(operation, operation);
    mutationTail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  function serializeBash<T>(operation: () => Promise<T>): Promise<T> {
    const run = bashTail.then(operation, operation);
    bashTail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  function getModeAllowances(mode = activeMode): SessionAllowances {
    let allowances = allowancesByMode.get(mode);
    if (!allowances) {
      allowances = newAllowances();
      allowancesByMode.set(mode, allowances);
    }
    return allowances;
  }

  function requirePolicy(): LoadedSandboxPolicy {
    if (!policy) throw new Error("Sandbox policy is not loaded");
    return policy;
  }

  function loadPolicySnapshot(
    ctx: Parameters<typeof warnIfAllDomainsAllowed>[0],
  ): LoadedSandboxPolicy {
    const loaded = loadPolicy(ctx.cwd, activeMode, ctx.isProjectTrusted());
    policy = loaded;
    projectRequestState = classifyProjectAccessRequests({
      requests: loaded.projectRequests,
      config: loaded.config,
      projectRoot: loaded.projectRoot,
      mode: activeMode,
      modePolicy: getModePolicy(activeMode),
      protectedWritePaths: loaded.protectedWritePaths,
      approval: loaded.projectRequestApproval,
    });
    for (const warning of loaded.warnings) ctx.ui.notify(`Sandbox policy: ${warning}`, "warning");
    return loaded;
  }

  function emptySelection(): ProjectRequestSelection {
    return { read: [], write: [], network: [] };
  }

  function hasSelection(selection: ProjectRequestSelection): boolean {
    return selection.read.length + selection.write.length + selection.network.length > 0;
  }

  function reclassifyProjectRequests(loaded: LoadedSandboxPolicy): ProjectRequestState {
    projectRequestState = classifyProjectAccessRequests({
      requests: loaded.projectRequests,
      config: loaded.config,
      projectRoot: loaded.projectRoot,
      mode: activeMode,
      modePolicy: getModePolicy(activeMode),
      protectedWritePaths: loaded.protectedWritePaths,
      approval: loaded.projectRequestApproval,
    });
    return projectRequestState;
  }

  async function reviewProjectRequests(
    loaded: LoadedSandboxPolicy,
    ctx: Parameters<typeof warnIfAllDomainsAllowed>[0],
  ): Promise<boolean> {
    let requestState = reclassifyProjectRequests(loaded);
    const pending = pendingProjectRequestCount(requestState);
    let newlyApproved = emptySelection();
    if (pending > 0) {
      if (!ctx.hasUI && ctx.mode !== "rpc") {
        ctx.ui.notify(
          `Project sandbox policy has ${pending} pending access request(s); non-interactive sessions never auto-approve them.`,
          "warning",
        );
      }
      const review = await promptProjectAccessRequests(ctx, requestState);
      if (review.action === "abort") return false;
      newlyApproved = review.approved;
    }

    const approved = approvedSelectionFromState(requestState, newlyApproved);
    const needsWrite =
      hasSelection(newlyApproved) ||
      (loaded.projectRequestApproval !== undefined &&
        loaded.projectRequestApproval.manifestHash !== requestState.manifestHash);
    if (needsWrite) {
      try {
        loaded.projectRequestApproval = writeProjectRequestApproval(
          loaded.paths.projectRequestApprovalPath,
          loaded.projectRoot,
          activeMode,
          loaded.projectRequests,
          approved,
        );
        requestState = reclassifyProjectRequests(loaded);
      } catch (error) {
        ctx.ui.notify(
          `Could not persist project access approval; requested access remains blocked: ${error}`,
          "error",
        );
        reclassifyProjectRequests(loaded);
      }
    }
    return true;
  }

  function declaredAllowances(): SessionAllowances {
    return projectRequestState ? declaredProjectAllowances(projectRequestState) : newAllowances();
  }

  function effectiveReadPaths(): string[] {
    const loaded = requirePolicy();
    const config = loaded.config;
    return resolvePolicyPatterns(
      [
        ...(config.filesystem.allowRead ?? []),
        ...config.filesystem.allowWrite,
        ...getModeAllowances().readPaths,
        ...getModeAllowances().writePaths,
        ...declaredAllowances().readPaths,
        ...declaredAllowances().writePaths,
      ],
      activeCtx?.cwd ?? localCwd,
    );
  }

  function effectiveWritePaths(): string[] {
    if (getModePolicy(activeMode).write === "deny") return [];
    const loaded = requirePolicy();
    return resolvePolicyPatterns(
      [
        ...loaded.config.filesystem.allowWrite,
        ...getModeAllowances().writePaths,
        ...declaredAllowances().writePaths,
      ],
      activeCtx?.cwd ?? localCwd,
    );
  }

  function runtimeConfigForActiveMode() {
    const loaded = requirePolicy();
    if (getModePolicy(activeMode).write !== "deny") return loaded.config;
    return {
      ...loaded.config,
      filesystem: { ...loaded.config.filesystem, allowWrite: [] },
    };
  }

  function runtimeAllowancesForActiveMode(): SessionAllowances {
    const session = getModeAllowances();
    const declared = declaredAllowances();
    const allowances = {
      domains: [...new Set([...session.domains, ...declared.domains])],
      readPaths: [...new Set([...session.readPaths, ...declared.readPaths])],
      writePaths: [...new Set([...session.writePaths, ...declared.writePaths])],
    };
    return getModePolicy(activeMode).write === "deny"
      ? { ...allowances, writePaths: [] }
      : allowances;
  }

  function updateStatus(ctx: Parameters<typeof warnIfAllDomainsAllowed>[0]): void {
    const loaded = requirePolicy();
    ctx.ui.setStatus(
      "sandbox",
      ctx.ui.theme.fg("accent", formatSandboxStatus(loaded.config, activeMode, state)),
    );
  }

  async function startSandbox(
    ctx: Parameters<typeof warnIfAllDomainsAllowed>[0],
    setProxyEnvironment: boolean,
  ): Promise<boolean> {
    activeCtx = ctx;
    const platform = process.platform;
    if (platform !== "darwin" && platform !== "linux") {
      state = "failed";
      ctx.ui.notify(`Sandbox not supported on ${platform}; agent bash is blocked`, "error");
      updateStatus(ctx);
      return false;
    }

    state = "initializing";
    updateStatus(ctx);
    try {
      const loaded = requirePolicy();
      await initializeSandbox(
        runtimeConfigForActiveMode(),
        runtimeAllowancesForActiveMode(),
        ctx.cwd,
        (host) => handleRuntimeBlockedDomain(host, ctx.cwd),
        loaded.protectedWritePaths,
        bootstrapShellPaths,
      );
      if (setProxyEnvironment && supportsNodeEnvProxy(process.versions.node)) {
        process.env.NODE_USE_ENV_PROXY ??= "1";
      }
      state = "active";
      warnIfAllDomainsAllowed(ctx, loaded.config);
      updateStatus(ctx);
      return true;
    } catch (error) {
      state = "failed";
      ctx.ui.notify(
        `Sandbox initialization failed; agent bash is blocked: ${error instanceof Error ? error.message : error}`,
        "error",
      );
      updateStatus(ctx);
      return false;
    }
  }

  async function refreshSandbox(cwd: string): Promise<void> {
    if (state !== "active") throw new Error(`sandbox is ${state}`);
    const loaded = requirePolicy();
    const previousConfig = SandboxManager.getConfig();
    await SandboxManager.reset();
    try {
      await initializeSandbox(
        runtimeConfigForActiveMode(),
        runtimeAllowancesForActiveMode(),
        cwd,
        (host) => handleRuntimeBlockedDomain(host, cwd),
        loaded.protectedWritePaths,
        bootstrapShellPaths,
      );
    } catch (error) {
      state = "failed";
      if (previousConfig) {
        try {
          await SandboxManager.reset();
          await SandboxManager.initialize(
            previousConfig,
            async ({ host }) => handleRuntimeBlockedDomain(host, cwd),
            true,
          );
          state = "active";
        } catch {
          // The previous sandbox could not be restored; failed remains fail-closed.
        }
      }
      throw error;
    } finally {
      if (activeCtx) updateStatus(activeCtx);
    }
  }

  function grantTarget(choice: Exclude<PermissionChoice, "abort">): string | undefined {
    if (choice === "session") return undefined;
    const paths = requirePolicy().paths;
    return choice === "project"
      ? paths.projectGrantPath
      : (paths.globalModePath ?? paths.globalBasePath);
  }

  async function applyChoice(
    choice: Exclude<PermissionChoice, "abort">,
    kind: GrantKind,
    value: string,
    cwd: string,
    refresh = true,
  ): Promise<void> {
    await serialize(async () => {
      const allowances = getModeAllowances();
      const list =
        kind === "domain"
          ? allowances.domains
          : kind === "read"
            ? allowances.readPaths
            : allowances.writePaths;
      const added = !list.includes(value);
      if (added) list.push(value);
      try {
        if (refresh) await refreshSandbox(cwd);
      } catch (error) {
        if (added) list.splice(list.indexOf(value), 1);
        throw error;
      }
      const target = grantTarget(choice);
      if (target) {
        if (kind === "domain") addDomainToConfig(target, value);
        else if (kind === "read") addReadPathToConfig(target, value);
        else addWritePathToConfig(target, value);
      }
    });
  }

  async function handleRuntimeBlockedDomain(host: string, cwd: string): Promise<boolean> {
    const loaded = requirePolicy();
    const allowed = [
      ...(loaded.config.network.allowedDomains ?? []),
      ...getModeAllowances().domains,
      ...declaredAllowances().domains,
    ];
    if (domainIsAllowed(host, allowed)) return true;
    const existing = pendingDomainPrompts.get(host);
    if (existing) return existing;
    const prompt = (async () => {
      if (getModePolicy(activeMode).network === "deny") return false;
      const ctx = activeToolCtx ?? activeCtx;
      if (!ctx) return false;
      const choice = await promptDomainBlock(ctx, host);
      if (choice === "abort") return false;
      await applyChoice(choice, "domain", host, ctx.cwd ?? cwd, false);
      SandboxManager.updateConfig(
        buildRuntimeConfig(
          runtimeConfigForActiveMode(),
          runtimeAllowancesForActiveMode(),
          ctx.cwd ?? cwd,
          loaded.protectedWritePaths,
          bootstrapShellPaths,
        ),
      );
      return true;
    })().finally(() => pendingDomainPrompts.delete(host));
    pendingDomainPrompts.set(host, prompt);
    return prompt;
  }

  function structuredHardReadPatterns(): string[] {
    const config = requirePolicy().config;
    return [
      ...config.filesystem.denyRead,
      ...(config.credentials?.files ?? []).map((entry) => entry.path),
    ];
  }

  function readDecision(path: string, cwd: string) {
    const loaded = requirePolicy();
    const config = loaded.config;
    return evaluateReadPolicy({
      path,
      cwd,
      readScope: config.filesystem.readScope ?? "home",
      denyRead: structuredHardReadPatterns(),
      allowRead: effectiveReadPaths(),
      modeBehavior: getModePolicy(activeMode).read,
    });
  }

  function isHardWriteDenied(path: string, cwd: string): boolean {
    const loaded = requirePolicy();
    return matchesPattern(
      path,
      [
        ...loaded.config.filesystem.denyWrite,
        ...structuredHardReadPatterns(),
        ...loaded.protectedWritePaths,
      ],
      cwd,
    );
  }

  pi.registerTool({
    ...localBash,
    label: "bash (sandboxed)",
    async execute(id, params, signal, onUpdate, ctx) {
      return serializeBash(async () => {
        if (state !== "active") {
          if (state === "disabled-by-user")
            return localBash.execute(id, params, signal, onUpdate, ctx);
          return textResult(`Blocked: sandbox state is ${state}; refusing unsandboxed agent bash.`);
        }
        activeToolCtx = ctx;
        let result: AgentToolResult<any>;
        try {
          result = await createBashToolDefinition(localCwd, {
            operations: createSandboxedBashOps(userShellPath),
            shellPath: userShellPath,
          }).execute(id, params, signal, onUpdate, ctx);
        } catch (error) {
          if (!(error instanceof Error) || !extractSandboxViolation(error.message)) throw error;
          result = textResult(`Command failed with OS-level sandbox restriction: ${error.message}`);
        } finally {
          activeToolCtx = undefined;
        }

        const output = result.content
          .filter((content: any) => content.type === "text")
          .map((content: any) => content.text)
          .join("\n");
        const violation = extractSandboxViolation(output);
        if (!violation) return result;

        if (violation.type === "read") {
          const decision = readDecision(violation.path, ctx.cwd);
          if (decision === "hard-deny" || decision === "mode-deny") return result;
          // Only macOS Seatbelt supplies attributable read-denial events.
          if (process.platform === "darwin") {
            const choice = await promptReadBlock(ctx, violation.path);
            if (choice !== "abort") {
              await applyChoice(choice, "read", canonicalizePath(violation.path, ctx.cwd), ctx.cwd);
              return textResult(
                `Read access granted for "${violation.path}". The command was not retried because it may already have produced side effects; run a fresh command.`,
              );
            }
          }
        } else if (violation.type === "write") {
          if (
            isHardWriteDenied(violation.path, ctx.cwd) ||
            getModePolicy(activeMode).write === "deny"
          ) {
            return result;
          }
          const choice = await promptWriteBlock(ctx, violation.path);
          if (choice !== "abort") {
            await applyChoice(choice, "write", canonicalizePath(violation.path, ctx.cwd), ctx.cwd);
            return textResult(
              `Write access granted for "${violation.path}". The command was not retried because it may already have produced side effects; run a fresh command.`,
            );
          }
        }
        return result;
      });
    },
  });

  pi.registerTool({
    name: "request_sandbox_access",
    label: "Request sandbox access",
    description:
      "Ask the user for explicit filesystem access. Use this when a sandboxed command needs a known path; this tool never grants access without user approval.",
    parameters: Type.Object({
      operation: Type.Union([Type.Literal("read"), Type.Literal("write")]),
      path: Type.String(),
      reason: Type.String(),
    }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      if (state !== "active") return textResult(`Sandbox is ${state}; access cannot be granted.`);
      const path = canonicalizePath(params.path, ctx.cwd);
      if (params.operation === "read" && readDecision(path, ctx.cwd) === "hard-deny") {
        return textResult(
          `Denied: "${path}" is covered by denyRead and cannot be granted interactively.`,
        );
      }
      if (params.operation === "write" && isHardWriteDenied(path, ctx.cwd)) {
        return textResult(`Denied: "${path}" is covered by a hard write deny.`);
      }
      const choice = await promptAccessRequest(ctx, params.operation, path, params.reason);
      if (choice === "abort")
        return textResult(`User denied ${params.operation} access to "${path}".`);
      await applyChoice(choice, params.operation, path, ctx.cwd);
      return textResult(`${params.operation} access granted for "${path}". Run a fresh operation.`);
    },
  });

  pi.on("user_bash", async () => {
    if (state === "active") {
      const operations = createSandboxedBashOps(userShellPath);
      return {
        operations: {
          exec: (...args: Parameters<typeof operations.exec>) =>
            serializeBash(() => operations.exec(...args)),
        },
      };
    }
    if (state === "disabled-by-user") return;
    return {
      result: {
        output: `Blocked: sandbox state is ${state}; refusing unsandboxed command.`,
        exitCode: 126,
        cancelled: false,
        truncated: false,
      },
    };
  });

  pi.on("tool_call", async (event, ctx) => {
    if (state !== "active") {
      if (state === "disabled-by-user") return;
      return { block: true, reason: `Sandbox is ${state}; tool execution is blocked fail-closed.` };
    }
    const pathForRecursiveTool =
      isToolCallEventType("grep", event) || isToolCallEventType("find", event)
        ? (event.input.path ?? ".")
        : isToolCallEventType("ls", event)
          ? (event.input.path ?? ".")
          : undefined;

    if (pathForRecursiveTool !== undefined) {
      const root = canonicalizePath(pathForRecursiveTool, ctx.cwd);
      const decision = readDecision(root, ctx.cwd);
      if (decision === "hard-deny" || decision === "mode-deny") {
        return {
          block: true,
          reason: `Sandbox blocks recursive read root "${root}" (${decision}).`,
        };
      }
      if (decision === "prompt") {
        const choice = await promptReadBlock(ctx, root);
        if (choice === "abort")
          return { block: true, reason: `Sandbox denied read access to "${root}".` };
        await applyChoice(choice, "read", root, ctx.cwd);
      }
      const nested = hardDeniesWithin(root, structuredHardReadPatterns(), ctx.cwd);
      if (nested.length) {
        return {
          block: true,
          reason:
            `Sandbox blocked recursive ${event.toolName} because "${root}" contains hard-denied descendants: ` +
            nested.join(", ") +
            ". Use a narrower allowed path.",
        };
      }
      return;
    }

    if (isToolCallEventType("read", event)) {
      const path = canonicalizePath(event.input.path, ctx.cwd);
      const decision = readDecision(path, ctx.cwd);
      if (decision === "hard-deny" || decision === "mode-deny") {
        return { block: true, reason: `Sandbox blocks read access to "${path}" (${decision}).` };
      }
      if (decision === "prompt") {
        const choice = await promptReadBlock(ctx, path);
        if (choice === "abort")
          return { block: true, reason: `Sandbox denied read access to "${path}".` };
        await applyChoice(choice, "read", path, ctx.cwd);
      }
      event.input.path = path;
      return;
    }

    if (isToolCallEventType("write", event) || isToolCallEventType("edit", event)) {
      const path = canonicalizePath(event.input.path, ctx.cwd);
      if (isHardWriteDenied(path, ctx.cwd)) {
        return { block: true, reason: `Sandbox hard-denies writes to "${path}".` };
      }
      if (getModePolicy(activeMode).write === "deny") {
        return { block: true, reason: `Sandbox mode "${activeMode}" denies writes.` };
      }
      if (!matchesPattern(path, effectiveWritePaths(), ctx.cwd)) {
        const choice = await promptWriteBlock(ctx, path);
        if (choice === "abort")
          return { block: true, reason: `Sandbox denied write access to "${path}".` };
        await applyChoice(choice, "write", path, ctx.cwd);
      }
      event.input.path = path;
    }
  });

  pi.on("session_start", async (_event, ctx) => {
    activeMode =
      ((pi.getFlag("sandbox-mode") as string | undefined) || DEFAULT_MODE).trim() || DEFAULT_MODE;
    activeCtx = ctx;
    try {
      const loaded = loadPolicySnapshot(ctx);
      if (pi.getFlag("no-sandbox") as boolean) {
        state = "disabled-by-user";
        ctx.ui.notify("Sandbox explicitly disabled via --no-sandbox", "warning");
        updateStatus(ctx);
        return;
      }
      if (!loaded.config.enabled) {
        state = "disabled-by-user";
        ctx.ui.notify("Sandbox disabled via trusted user configuration", "warning");
        updateStatus(ctx);
        return;
      }
      if (!(await reviewProjectRequests(loaded, ctx))) {
        state = "failed";
        ctx.ui.notify("Sandbox startup aborted while reviewing project access requests", "warning");
        updateStatus(ctx);
        return;
      }
      await startSandbox(ctx, true);
    } catch (error) {
      state = "failed";
      ctx.ui.notify(`Sandbox policy failed to load; tools are blocked: ${error}`, "error");
    }
  });

  pi.on("session_shutdown", async () => {
    if (state !== "active") return;
    try {
      await SandboxManager.reset();
    } catch {
      // Cleanup is best effort; no more tools run after shutdown.
    }
  });

  pi.registerCommand("sandbox-enable", {
    description: "Enable the sandbox for this session",
    handler: async (_args, ctx) => {
      try {
        if (state === "active") return void ctx.ui.notify("Sandbox is already enabled", "info");
        const loaded = loadPolicySnapshot(ctx);
        if (!(await reviewProjectRequests(loaded, ctx))) {
          return void ctx.ui.notify("Sandbox enable aborted during access review", "warning");
        }
        if (await startSandbox(ctx, false)) ctx.ui.notify("Sandbox enabled", "info");
      } catch (error) {
        state = "failed";
        ctx.ui.notify(`Sandbox could not be enabled: ${error}`, "error");
      }
    },
  });

  pi.registerCommand("sandbox-disable", {
    description: "Explicitly disable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (state === "active") await SandboxManager.reset();
      state = "disabled-by-user";
      updateStatus(ctx);
      ctx.ui.notify("Sandbox explicitly disabled; commands run with user permissions", "warning");
    },
  });

  pi.registerCommand("sandbox-mode", {
    description: "Show or switch sandbox mode",
    handler: async (args, ctx) => {
      const requestedMode = commandArgText(args);
      if (!requestedMode) return void ctx.ui.notify(`Active sandbox mode: ${activeMode}`, "info");
      await serialize(async () => {
        const previousMode = activeMode;
        const previousPolicy = policy;
        const previousRequestState = projectRequestState;
        activeMode = requestedMode;
        try {
          const loaded = loadPolicySnapshot(ctx);
          if (!(await reviewProjectRequests(loaded, ctx))) {
            throw new Error("mode switch aborted during project access review");
          }
          if (state === "active") await refreshSandbox(ctx.cwd);
          updateStatus(ctx);
        } catch (error) {
          activeMode = previousMode;
          policy = previousPolicy;
          projectRequestState = previousRequestState;
          throw error;
        }
      });
      ctx.ui.notify(`Sandbox mode switched to "${activeMode}"`, "info");
    },
  });

  async function commandGrant(
    kind: "read" | "write",
    args: unknown,
    ctx: Parameters<typeof warnIfAllDomainsAllowed>[0],
  ) {
    const raw = commandArgText(args);
    if (!raw) return void ctx.ui.notify(`Usage: /sandbox-allow-${kind} <path>`, "warning");
    const path = canonicalizePath(raw, ctx.cwd);
    if (kind === "read" && readDecision(path, ctx.cwd) === "hard-deny") {
      return void ctx.ui.notify(`Cannot grant hard-denied read path: ${path}`, "error");
    }
    if (kind === "write" && isHardWriteDenied(path, ctx.cwd)) {
      return void ctx.ui.notify(`Cannot grant hard-denied write path: ${path}`, "error");
    }
    await applyChoice("session", kind, path, ctx.cwd);
    ctx.ui.notify(`Session ${kind} access granted: ${path}`, "info");
  }

  pi.registerCommand("sandbox-allow-read", {
    description: "Grant session read access to an explicit path",
    handler: (args, ctx) => commandGrant("read", args, ctx),
  });
  pi.registerCommand("sandbox-allow-write", {
    description: "Grant session write access to an explicit path",
    handler: (args, ctx) => commandGrant("write", args, ctx),
  });

  pi.registerCommand("sandbox", {
    description: "Show effective sandbox configuration",
    handler: async (_args, ctx) => {
      if (!policy) return void ctx.ui.notify(`Sandbox is ${state}`, "info");
      ctx.ui.notify(
        formatSandboxConfiguration(
          policy,
          getModeAllowances(),
          activeMode,
          state,
          [
            ...getRuntimeBootstrapReadPaths(
              ctx.cwd,
              policy.config.filesystem.readScope === "strict",
            ),
            ...bootstrapShellPaths,
          ],
          projectRequestState,
        ),
        "info",
      );
    },
  });
}
