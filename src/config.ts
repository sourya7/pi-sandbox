import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

export interface SandboxConfig extends SandboxRuntimeConfig {
  enabled?: boolean;
}

export interface SandboxConfigPaths {
  globalBasePath: string;
  globalModePath?: string;
  projectBasePath: string;
  projectModePath?: string;
}

export const DEFAULT_CONFIG: SandboxConfig = {
  enabled: true,
  network: {
    allowedDomains: [
      "npmjs.org",
      "*.npmjs.org",
      "registry.npmjs.org",
      "registry.yarnpkg.com",
      "pypi.org",
      "*.pypi.org",
      "github.com",
      "*.github.com",
      "api.github.com",
      "raw.githubusercontent.com",
    ],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: ["/Users", "/home"],
    allowRead: [".", "~/.config", "~/.local", "Library"],
    allowWrite: [".", "/tmp"],
    denyWrite: [".env", ".env.*", "*.pem", "*.key"],
  },
};

function mergeList(base?: string[], override?: string[]): string[] | undefined {
  if (!base && !override) return undefined;
  return [...new Set([...(base ?? []), ...(override ?? [])])];
}

export function deepMerge(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
  const result: SandboxConfig = { ...base };

  if (overrides.enabled !== undefined) result.enabled = overrides.enabled;
  if (overrides.network) {
    result.network = {
      ...base.network,
      ...overrides.network,
      allowedDomains:
        mergeList(base.network?.allowedDomains, overrides.network.allowedDomains) ?? [],
      deniedDomains: mergeList(base.network?.deniedDomains, overrides.network.deniedDomains) ?? [],
    };
  }
  if (overrides.filesystem) {
    result.filesystem = {
      ...base.filesystem,
      ...overrides.filesystem,
      allowRead: mergeList(base.filesystem?.allowRead, overrides.filesystem.allowRead) ?? [],
      denyRead: mergeList(base.filesystem?.denyRead, overrides.filesystem.denyRead) ?? [],
      allowWrite: mergeList(base.filesystem?.allowWrite, overrides.filesystem.allowWrite) ?? [],
      denyWrite: mergeList(base.filesystem?.denyWrite, overrides.filesystem.denyWrite) ?? [],
    };
  }

  if (overrides.ignoreViolations) result.ignoreViolations = overrides.ignoreViolations;
  if (overrides.enableWeakerNestedSandbox !== undefined) {
    result.enableWeakerNestedSandbox = overrides.enableWeakerNestedSandbox;
  }

  return result;
}

function readJsonConfig(configPath: string, warn: boolean): Partial<SandboxConfig> {
  if (!existsSync(configPath)) return {};
  try {
    return JSON.parse(readFileSync(configPath, "utf-8"));
  } catch (error) {
    if (warn) console.error(`Warning: Could not parse ${configPath}: ${error}`);
    return {};
  }
}

function modeSuffix(mode: string): string {
  return mode && mode !== "default" ? `.${mode}` : "";
}

export function getConfigPaths(cwd: string, mode = "default"): SandboxConfigPaths {
  const suffix = modeSuffix(mode);
  return {
    globalBasePath: join(getAgentDir(), "sandbox.json"),
    globalModePath: suffix ? join(getAgentDir(), `sandbox${suffix}.json`) : undefined,
    projectBasePath: join(cwd, ".pi", "sandbox.json"),
    projectModePath: suffix ? join(cwd, ".pi", `sandbox${suffix}.json`) : undefined,
  };
}

export function loadConfig(cwd: string, mode = "default"): SandboxConfig {
  const paths = getConfigPaths(cwd, mode);
  const globalBaseConfig = readJsonConfig(paths.globalBasePath, true);
  const globalModeConfig = paths.globalModePath ? readJsonConfig(paths.globalModePath, true) : {};
  const projectBaseConfig = readJsonConfig(paths.projectBasePath, true);
  const projectModeConfig = paths.projectModePath
    ? readJsonConfig(paths.projectModePath, true)
    : {};

  return deepMerge(
    deepMerge(
      deepMerge(deepMerge(DEFAULT_CONFIG, globalBaseConfig), globalModeConfig),
      projectBaseConfig,
    ),
    projectModeConfig,
  );
}

function writeConfigFile(configPath: string, config: Partial<SandboxConfig>): void {
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
}

export function addDomainToConfig(configPath: string, domain: string): void {
  const config = readJsonConfig(configPath, false);
  const existing = config.network?.allowedDomains ?? [];
  if (existing.includes(domain)) return;

  config.network = {
    ...config.network,
    allowedDomains: [...existing, domain],
    deniedDomains: config.network?.deniedDomains ?? [],
  };
  writeConfigFile(configPath, config);
}

export function addReadPathToConfig(configPath: string, pathToAdd: string): void {
  const config = readJsonConfig(configPath, false);
  const existing = config.filesystem?.allowRead ?? [];
  if (existing.includes(pathToAdd)) return;

  config.filesystem = {
    ...config.filesystem,
    allowRead: [...existing, pathToAdd],
    denyRead: config.filesystem?.denyRead ?? [],
    allowWrite: config.filesystem?.allowWrite ?? [],
    denyWrite: config.filesystem?.denyWrite ?? [],
  };
  writeConfigFile(configPath, config);
}

export function addWritePathToConfig(configPath: string, pathToAdd: string): void {
  const config = readJsonConfig(configPath, false);
  const existing = config.filesystem?.allowWrite ?? [];
  if (existing.includes(pathToAdd)) return;

  config.filesystem = {
    ...config.filesystem,
    allowWrite: [...existing, pathToAdd],
    denyRead: config.filesystem?.denyRead ?? [],
    denyWrite: config.filesystem?.denyWrite ?? [],
  };
  writeConfigFile(configPath, config);
}
