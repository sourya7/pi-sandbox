import { type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Key, matchesKey, truncateToWidth } from "@earendil-works/pi-tui";

import {
  type ClassifiedDomainRequest,
  type ClassifiedPathRequest,
  type ProjectRequestSelection,
  type ProjectRequestState,
} from "./access-requests.ts";
import { type LoadedSandboxPolicy, type SandboxConfig } from "./config.ts";
import { DEFAULT_MODE, getModePolicy } from "./modes.ts";
import { allowsAllDomains } from "./policy.ts";
import { type SessionAllowances } from "./sandbox-runtime.ts";
import { type ExactSessionOverride } from "./session-overrides.ts";

export type PermissionChoice = "abort" | "session" | "project" | "global";

interface PromptOption {
  label: string;
  key: string;
  action: PermissionChoice;
  confirm?: boolean;
  hint?: string;
}

const PERMISSION_OPTIONS: PromptOption[] = [
  { label: "Allow for this session only", key: "s", action: "session" },
  { label: "Abort (keep blocked)", key: "esc", action: "abort" },
  {
    label: "Allow for this project",
    key: "P",
    action: "project",
    confirm: true,
    hint: "→ user-owned project grant",
  },
  {
    label: "Allow for all projects",
    key: "A",
    action: "global",
    confirm: true,
    hint: "→ ~/.pi/agent/sandbox.json",
  },
];

function permissionOptionLabel(option: PromptOption): string {
  return option.hint ? `${option.label}  ${option.hint}` : option.label;
}

async function showRpcPermissionPrompt(
  ctx: ExtensionContext,
  title: string,
): Promise<PermissionChoice> {
  const labels = PERMISSION_OPTIONS.map(permissionOptionLabel);
  const selected = await ctx.ui.select(title, labels);
  const selectedIndex = selected ? labels.indexOf(selected) : -1;

  return selectedIndex >= 0 ? PERMISSION_OPTIONS[selectedIndex].action : "abort";
}

export async function showPermissionPrompt(
  ctx: ExtensionContext,
  title: string,
): Promise<PermissionChoice> {
  if (ctx.mode === "rpc") return showRpcPermissionPrompt(ctx, title);
  if (!ctx.hasUI) return "abort";

  const result = await ctx.ui.custom<PermissionChoice>((tui, theme, _kb, done) => {
    let selectedIndex = 0;
    let pendingAction: PermissionChoice | null = null;
    const resolve = (action: PermissionChoice) => done(action);

    return {
      render(width: number): string[] {
        const lines = [truncateToWidth(theme.fg("warning", title), width), ""];
        for (let i = 0; i < PERMISSION_OPTIONS.length; i++) {
          const option = PERMISSION_OPTIONS[i];
          const prefix = i === selectedIndex ? " → " : "   ";
          const keyHint = theme.fg("accent", `[${option.key}]`);
          let label = option.label;
          if (option.hint) label += `  ${theme.fg("dim", option.hint)}`;
          if (pendingAction === option.action) {
            label += `  ${theme.fg("warning", "→ press Enter to confirm")}`;
          }
          lines.push(truncateToWidth(`${prefix}${keyHint} ${label}`, width));
        }
        lines.push("");
        const footer = pendingAction
          ? "↑↓ navigate  enter confirm  esc cancel"
          : "↑↓ navigate  enter select  esc/ctrl+c cancel";
        lines.push(truncateToWidth(theme.fg("dim", footer), width));
        return lines;
      },
      handleInput(data: string): void {
        if (matchesKey(data, Key.escape) || matchesKey(data, Key.ctrl("c"))) {
          resolve("abort");
          return;
        }
        if (matchesKey(data, Key.enter)) {
          resolve(pendingAction ?? PERMISSION_OPTIONS[selectedIndex]?.action ?? "abort");
          return;
        }
        if (matchesKey(data, Key.up) || matchesKey(data, Key.down)) {
          const delta = matchesKey(data, Key.up) ? -1 : 1;
          selectedIndex = Math.max(
            0,
            Math.min(PERMISSION_OPTIONS.length - 1, selectedIndex + delta),
          );
          pendingAction = null;
          tui.requestRender();
          return;
        }
        for (let i = 0; i < PERMISSION_OPTIONS.length; i++) {
          const option = PERMISSION_OPTIONS[i];
          if (data === option.key) {
            resolve(option.action);
            return;
          }
          if (data.toLowerCase() === option.key.toLowerCase()) {
            if (option.confirm) {
              pendingAction = option.action;
              selectedIndex = i;
            } else {
              resolve(option.action);
            }
            tui.requestRender();
            return;
          }
        }
      },
      invalidate(): void {},
    };
  });

  return result ?? "abort";
}

export function promptDomainBlock(
  ctx: ExtensionContext,
  domain: string,
): Promise<PermissionChoice> {
  return showPermissionPrompt(ctx, `🌐 Network blocked: "${domain}" is not in allowedDomains`);
}

export function promptReadBlock(ctx: ExtensionContext, path: string): Promise<PermissionChoice> {
  return showPermissionPrompt(ctx, `📖 Read blocked: "${path}" is not in allowRead`);
}

export function promptWriteBlock(ctx: ExtensionContext, path: string): Promise<PermissionChoice> {
  return showPermissionPrompt(ctx, `📝 Write blocked: "${path}" is not in allowWrite`);
}

export function promptAccessRequest(
  ctx: ExtensionContext,
  operation: "read" | "write",
  path: string,
  reason: string,
): Promise<PermissionChoice> {
  const icon = operation === "read" ? "📖" : "📝";
  return showPermissionPrompt(
    ctx,
    `${icon} Agent requests ${operation} access to "${path}"\nReason: ${reason}`,
  );
}

export type ProjectAccessReviewResult =
  | { action: "continue"; approved: ProjectRequestSelection }
  | { action: "abort"; approved: ProjectRequestSelection };

const emptyProjectSelection = (): ProjectRequestSelection => ({
  read: [],
  write: [],
  network: [],
});

export function formatProjectAccessRequestSummary(
  state: ProjectRequestState,
  onlyPending = true,
): string {
  const include = (status: string) => !onlyPending || status === "pending";
  const read = state.readPaths.filter((entry) => include(entry.status));
  const write = state.writePaths.filter((entry) => include(entry.status));
  const network = state.domains.filter((entry) => include(entry.status));
  const lines = ["This project requests additional sandbox access:"];
  if (read.length) lines.push("", "Read:", ...read.map((entry) => `  ${entry.canonicalPath}`));
  if (write.length) {
    lines.push(
      "",
      "Write (also grants read):",
      ...write.map((entry) => `  ${entry.canonicalPath}`),
    );
  }
  if (network.length) lines.push("", "Network:", ...network.map((entry) => `  ${entry.domain}`));
  return lines.join("\n");
}

export async function promptProjectAccessRequests(
  ctx: ExtensionContext,
  state: ProjectRequestState,
  signal?: AbortSignal,
): Promise<ProjectAccessReviewResult> {
  const empty = emptyProjectSelection();
  if (!ctx.hasUI && ctx.mode !== "rpc") return { action: "continue", approved: empty };

  const summary = formatProjectAccessRequestSummary(state);
  const options = [
    "Approve all for this project",
    "Review individually",
    "Continue with requests blocked",
    "Abort session startup",
  ];
  const choice = await ctx.ui.select(summary, options, { signal });
  if (choice === options[3]) return { action: "abort", approved: empty };
  if (choice === options[2] || !choice) return { action: "continue", approved: empty };

  const pendingRead = state.readPaths.filter((entry) => entry.status === "pending");
  const pendingWrite = state.writePaths.filter((entry) => entry.status === "pending");
  const pendingNetwork = state.domains.filter((entry) => entry.status === "pending");
  if (choice === options[0]) {
    const confirmed = await ctx.ui.select(
      `${summary}\n\nPersist these approvals in the user-owned project approval file?`,
      ["Confirm approval", "Cancel"],
      { signal },
    );
    if (confirmed !== "Confirm approval") return { action: "continue", approved: empty };
    return {
      action: "continue",
      approved: {
        read: pendingRead.map((entry) => entry.canonicalPath),
        write: pendingWrite.map((entry) => entry.canonicalPath),
        network: pendingNetwork.map((entry) => entry.domain),
      },
    };
  }

  const approved = emptyProjectSelection();
  const review = async (label: string, value: string): Promise<boolean> =>
    (await ctx.ui.select(
      `Approve project ${label} access?\n\n${value}`,
      ["Approve", "Keep blocked"],
      { signal },
    )) === "Approve";
  for (const entry of pendingRead) {
    if (await review("read", entry.canonicalPath)) approved.read.push(entry.canonicalPath);
  }
  for (const entry of pendingWrite) {
    if (await review("write (also read)", entry.canonicalPath)) {
      approved.write.push(entry.canonicalPath);
    }
  }
  for (const entry of pendingNetwork) {
    if (await review("network", entry.domain)) approved.network.push(entry.domain);
  }
  return { action: "continue", approved };
}

export function warnIfAllDomainsAllowed(ctx: ExtensionContext, config: SandboxConfig): void {
  if (!allowsAllDomains(config.network?.allowedDomains)) return;
  ctx.ui.notify(
    '⚠️ Network sandbox allows all domains because network.allowedDomains contains "*". ' +
      'Only use this intentionally; remove "*" to restore per-domain prompts.',
    "warning",
  );
}

export function formatSandboxStatus(
  config: SandboxConfig,
  mode = DEFAULT_MODE,
  state: "disabled-by-user" | "initializing" | "active" | "failed" = "active",
  exactOverrideCount = 0,
): string {
  if (state === "failed") return "⛔ Sandbox unavailable — tools blocked";
  if (state === "initializing") return "⏳ Sandbox initializing — tools blocked";
  if (state === "disabled-by-user") return "⚠️ Sandbox explicitly disabled";
  const networkLabel = allowsAllDomains(config.network?.allowedDomains)
    ? "all domains"
    : `${config.network?.allowedDomains?.length ?? 0} domains`;
  const modePolicy = getModePolicy(mode);
  const writeLabel =
    modePolicy.write === "deny"
      ? "writes denied"
      : `${config.filesystem.allowWrite.length} write paths`;
  const scope = config.filesystem.readScope ?? "home";
  const overrideLabel = exactOverrideCount
    ? ` · ⚠️ ${exactOverrideCount} exact deny override${exactOverrideCount === 1 ? "" : "s"}`
    : "";
  return `🔒 Sandbox: ${mode}${overrideLabel} · read ${scope} · ${writeLabel} · ${networkLabel}`;
}

function formatPathRequest(entry: ClassifiedPathRequest): string[] {
  const configured = entry.configuredValues.join(", ");
  const spelling = entry.configuredValues.includes(entry.canonicalPath)
    ? entry.canonicalPath
    : `${configured} -> ${entry.canonicalPath}`;
  return [
    `    ${spelling}`,
    `      status: ${entry.status}`,
    `      source: ${entry.sources.map((source) => source.sourcePath).join(", ")}`,
  ];
}

function formatDomainRequest(entry: ClassifiedDomainRequest): string[] {
  return [
    `    ${entry.domain}`,
    `      status: ${entry.status}`,
    `      source: ${entry.sources.map((source) => source.sourcePath).join(", ")}`,
  ];
}

function formatProjectRequestDiagnostics(state?: ProjectRequestState): string[] {
  if (!state) return ["Project policy requests: (not classified)"];
  const lines = [
    "Project policy requests:",
    `  Manifest: ${state.manifestHash}`,
    `  Approved at: ${state.approval?.approvedAt ?? "(no approval record)"}`,
  ];
  if (state.readPaths.length) {
    lines.push("  Read:", ...state.readPaths.flatMap(formatPathRequest));
  }
  if (state.writePaths.length) {
    lines.push("  Write:", ...state.writePaths.flatMap(formatPathRequest));
  }
  if (state.domains.length) {
    lines.push("  Network:", ...state.domains.flatMap(formatDomainRequest));
  }
  if (!state.readPaths.length && !state.writePaths.length && !state.domains.length) {
    lines.push("  (none)");
  }
  return lines;
}

export function formatSandboxConfiguration(
  loaded: LoadedSandboxPolicy,
  allowances: SessionAllowances,
  mode = DEFAULT_MODE,
  state: "disabled-by-user" | "initializing" | "active" | "failed" = "active",
  bootstrapReadPaths: string[] = [],
  projectRequestState?: ProjectRequestState,
  effectiveConfig: SandboxConfig = loaded.config,
  exactOverrides: ExactSessionOverride[] = [],
): string {
  const { config, paths } = loaded;
  const modePolicy = getModePolicy(mode);
  return [
    "Sandbox Configuration",
    `  State: ${state}`,
    "  Policy version: 2",
    `  Active mode: ${mode}`,
    `  Project policy trusted: ${loaded.projectTrusted ? "yes" : "no"}`,
    `  Read scope: ${config.filesystem.readScope ?? "home"}`,
    "  Mode policy:",
    `    Read:    ${modePolicy.read}`,
    `    Write:   ${modePolicy.write}`,
    `    Network: ${modePolicy.network}`,
    "",
    "Config files:",
    `  Global base:  ${paths.globalBasePath}`,
    `  Global mode:  ${paths.globalModePath ?? "(none)"}`,
    `  Project base: ${paths.projectBasePath}`,
    `  Project mode: ${paths.projectModePath ?? "(none)"}`,
    `  Reactive project grants (user-owned): ${paths.projectGrantPath}`,
    `  Declared request approvals: ${paths.projectRequestApprovalPath}`,
    "",
    ...formatProjectRequestDiagnostics(projectRequestState),
    "",
    "Network (sandboxed bash + !cmd):",
    `  Direct global/default allowed: ${loaded.directConfig.network?.allowedDomains?.join(", ") || "(none)"}`,
    `  Reactive project allowed: ${loaded.reactiveProjectGrant?.network?.allowedDomains?.join(", ") || "(none)"}`,
    `  Effective allowed: ${config.network?.allowedDomains?.join(", ") || "(none)"}`,
    ...(allowsAllDomains(config.network?.allowedDomains)
      ? ['  ⚠️ "*" allows all domains and disables per-domain prompts.']
      : []),
    `  Denied domains:  ${config.network?.deniedDomains?.join(", ") || "(none)"}`,
    ...(allowances.domains.length ? [`  Session allowed: ${allowances.domains.join(", ")}`] : []),
    "",
    "Filesystem:",
    `  Configured hard deny read: ${config.filesystem.denyRead.join(", ") || "(none)"}`,
    `  Effective hard deny read:  ${effectiveConfig.filesystem.denyRead.join(", ") || "(none)"}`,
    `  Direct global/default read:  ${loaded.directConfig.filesystem.allowRead?.join(", ") || "(none)"}`,
    `  Direct global/default write: ${loaded.directConfig.filesystem.allowWrite.join(", ") || "(none)"}`,
    `  Reactive project read:  ${loaded.reactiveProjectGrant?.filesystem?.allowRead?.join(", ") || "(none)"}`,
    `  Reactive project write: ${loaded.reactiveProjectGrant?.filesystem?.allowWrite?.join(", ") || "(none)"}`,
    `  Effective allow read:  ${config.filesystem.allowRead?.join(", ") || "(none)"}`,
    `  Effective allow write: ${config.filesystem.allowWrite.join(", ") || "(none)"}`,
    "  Implicit read:  every allowWrite path (except hard-denied descendants)",
    `  Bootstrap read: ${[...new Set(bootstrapReadPaths)].join(", ") || "(none)"}`,
    `  Configured deny write: ${config.filesystem.denyWrite.join(", ") || "(none)"}`,
    `  Effective deny write:  ${effectiveConfig.filesystem.denyWrite.join(", ") || "(none)"}`,
    ...(allowances.readPaths.length
      ? [`  Session read:    ${allowances.readPaths.join(", ")}`]
      : []),
    ...(allowances.writePaths.length
      ? [`  Session write:   ${allowances.writePaths.join(", ")}`]
      : []),
    "  Exact session deny overrides:",
    ...(exactOverrides.length
      ? exactOverrides.flatMap((override) => [
          `    ${override.operation}: ${override.canonicalPath}`,
          `      removed: ${override.removedRules.map((rule) => `${rule.field} ${rule.configuredValue}`).join(", ")}`,
          "      lifetime: active mode and session only",
        ])
      : ["    (none)"]),
    `  Protected policy files: ${loaded.protectedWritePaths.join(", ")}`,
    "",
    "Isolation controls:",
    `  Filesystem disabled: ${config.filesystem.disabled === true ? "YES" : "no"}`,
    `  Weaker network isolation: ${config.enableWeakerNetworkIsolation === true ? "YES" : "no"}`,
    `  Weaker nested sandbox: ${config.enableWeakerNestedSandbox === true ? "YES" : "no"}`,
    `  Credential rules configured: ${config.credentials ? "yes" : "no; child environment may contain credentials"}`,
    "",
    ...(loaded.warnings.length
      ? ["Warnings:", ...loaded.warnings.map((warning) => `  ${warning}`), ""]
      : []),
    process.platform === "darwin"
      ? "macOS bash: attributable unknown reads may be prompted after failure; commands are never retried automatically."
      : "Linux bash: unknown reads fail closed; use request_sandbox_access or /sandbox-allow-read.",
    "Recursive grep/find/ls are blocked when their root contains a hard-denied descendant.",
    "Trusted custom extensions/tools are outside this extension's automatic boundary.",
  ].join("\n");
}
