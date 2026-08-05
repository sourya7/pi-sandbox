import { basename } from "node:path";

import { type SandboxConfig } from "./config.ts";
import { canonicalizePath } from "./policy.ts";

export type ExactOverrideOperation = "read" | "write";
export type OverrideDenyField = "denyRead" | "denyWrite";

export interface RemovedDenyRule {
  field: OverrideDenyField;
  configuredValue: string;
}

export interface ExactSessionOverride {
  operation: ExactOverrideOperation;
  configuredValue: string;
  canonicalPath: string;
  removedRules: RemovedDenyRule[];
  createdAt: string;
}

export interface ExactOverrideClassification {
  canonicalPath: string;
  exactRules: RemovedDenyRule[];
  broaderRules: RemovedDenyRule[];
  nonOverridableRules: Array<{ source: string; configuredValue: string }>;
}

function ruleRoot(rule: string, cwd: string): string {
  const raw = rule.endsWith("/**") ? rule.slice(0, -3) || "/" : rule;
  return canonicalizePath(raw, cwd);
}

function isAtOrBelow(candidate: string, root: string): boolean {
  return candidate === root || candidate.startsWith(root === "/" ? "/" : `${root}/`);
}

function configuredCoverage(
  field: OverrideDenyField,
  rules: string[],
  canonicalPath: string,
  cwd: string,
): Pick<ExactOverrideClassification, "exactRules" | "broaderRules"> {
  const exactRules: RemovedDenyRule[] = [];
  const broaderRules: RemovedDenyRule[] = [];
  for (const configuredValue of rules) {
    const root = ruleRoot(configuredValue, cwd);
    if (!isAtOrBelow(canonicalPath, root)) continue;
    const target = root === canonicalPath ? exactRules : broaderRules;
    target.push({ field, configuredValue });
  }
  return { exactRules, broaderRules };
}

const MANDATORY_WRITE_FILES = new Set([
  ".gitconfig",
  ".gitmodules",
  ".bashrc",
  ".bash_profile",
  ".zshrc",
  ".zprofile",
  ".profile",
  ".ripgreprc",
  ".mcp.json",
]);

function mandatoryWriteProtection(
  path: string,
  cwd: string,
  allowGitConfig: boolean,
): string | null {
  const relative = path.startsWith(`${cwd}/`) ? path.slice(cwd.length + 1) : basename(path);
  const segments = relative.split("/");
  if (MANDATORY_WRITE_FILES.has(basename(path))) return `mandatory file ${basename(path)}`;
  if (segments.includes(".vscode") || segments.includes(".idea")) {
    return "mandatory editor configuration directory";
  }
  const claude = segments.indexOf(".claude");
  if (claude >= 0 && ["commands", "agents"].includes(segments[claude + 1] ?? "")) {
    return "mandatory Claude command/agent directory";
  }
  const git = segments.indexOf(".git");
  if (git >= 0 && segments[git + 1] === "hooks") return "mandatory Git hooks directory";
  if (!allowGitConfig && git >= 0 && segments[git + 1] === "config") {
    return "mandatory Git configuration";
  }
  return null;
}

export function classifyExactSessionOverride(input: {
  operation: ExactOverrideOperation;
  path: string;
  config: SandboxConfig;
  cwd: string;
  protectedWritePaths?: string[];
}): ExactOverrideClassification {
  const canonicalPath = canonicalizePath(input.path, input.cwd);
  const fields: Array<[OverrideDenyField, string[]]> = [
    ["denyRead", input.config.filesystem.denyRead],
  ];
  if (input.operation === "write") fields.push(["denyWrite", input.config.filesystem.denyWrite]);

  const exactRules: RemovedDenyRule[] = [];
  const broaderRules: RemovedDenyRule[] = [];
  for (const [field, rules] of fields) {
    const coverage = configuredCoverage(field, rules, canonicalPath, input.cwd);
    exactRules.push(...coverage.exactRules);
    broaderRules.push(...coverage.broaderRules);
  }

  const nonOverridableRules: ExactOverrideClassification["nonOverridableRules"] = [];
  for (const entry of input.config.credentials?.files ?? []) {
    const root = ruleRoot(entry.path, input.cwd);
    if (isAtOrBelow(canonicalPath, root)) {
      nonOverridableRules.push({
        source: `credential ${entry.mode}`,
        configuredValue: entry.path,
      });
    }
  }
  if (input.operation === "write") {
    for (const protectedPath of input.protectedWritePaths ?? []) {
      const root = canonicalizePath(protectedPath, input.cwd);
      if (isAtOrBelow(canonicalPath, root)) {
        nonOverridableRules.push({
          source: "sandbox control-plane protection",
          configuredValue: protectedPath,
        });
      }
    }
    const mandatory = mandatoryWriteProtection(
      canonicalPath,
      canonicalizePath(input.cwd),
      input.config.filesystem.allowGitConfig === true,
    );
    if (mandatory) {
      nonOverridableRules.push({ source: mandatory, configuredValue: canonicalPath });
    }
  }

  return { canonicalPath, exactRules, broaderRules, nonOverridableRules };
}

export function deriveConfigWithExactOverrides(
  config: SandboxConfig,
  overrides: ExactSessionOverride[],
  cwd: string,
): SandboxConfig {
  const derived = structuredClone(config);
  const readRoots = new Set(
    overrides
      .filter((override) => override.operation === "read" || override.operation === "write")
      .map((override) => override.canonicalPath),
  );
  const writeRoots = new Set(
    overrides
      .filter((override) => override.operation === "write")
      .map((override) => override.canonicalPath),
  );
  derived.filesystem.denyRead = derived.filesystem.denyRead.filter(
    (rule) => !readRoots.has(ruleRoot(rule, cwd)),
  );
  derived.filesystem.denyWrite = derived.filesystem.denyWrite.filter(
    (rule) => !writeRoots.has(ruleRoot(rule, cwd)),
  );
  return derived;
}

export function canAuthorizeSessionGrant(mode: string, hasUI: boolean): boolean {
  return hasUI && (mode === "tui" || mode === "rpc");
}

export function formatSessionGrantConfirmation(input: {
  operation: ExactOverrideOperation;
  classification: ExactOverrideClassification;
  mode: string;
}): { title: string; message: string } {
  const ruleLines = input.classification.exactRules.length
    ? input.classification.exactRules
        .map((rule) => `  ${rule.field} ${rule.configuredValue}`)
        .join("\n")
    : "  (no configured deny rules; ordinary session grant)";
  return {
    title: `Temporarily grant sandbox ${input.operation} access?`,
    message: [
      `Path: ${input.classification.canonicalPath}`,
      `Mode: ${input.mode}`,
      "Rules temporarily removed:",
      ruleLines,
      "",
      `This grants agent tools and sandboxed commands ${input.operation} access for the active mode and session.`,
      "It does not modify sandbox policy files.",
    ].join("\n"),
  };
}

export function overrideAllowances(overrides: ExactSessionOverride[]): {
  readPaths: string[];
  writePaths: string[];
} {
  const readPaths = new Set<string>();
  const writePaths = new Set<string>();
  for (const override of overrides) {
    readPaths.add(override.canonicalPath);
    if (override.operation === "write") writePaths.add(override.canonicalPath);
  }
  return { readPaths: [...readPaths], writePaths: [...writePaths] };
}
