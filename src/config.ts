import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

import { type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { getAgentDir } from "@earendil-works/pi-coding-agent";

import { canonicalizePath } from "./policy.ts";

export type ReadScope = "home" | "strict" | "open";

export interface SandboxFilesystemConfig {
  disabled?: boolean;
  readScope?: ReadScope;
  denyRead: string[];
  allowRead?: string[];
  allowWrite: string[];
  denyWrite: string[];
  allowGitConfig?: boolean;
}

export interface SandboxConfig extends Omit<SandboxRuntimeConfig, "filesystem"> {
  policyVersion?: 1 | 2;
  enabled?: boolean;
  failClosed?: boolean;
  filesystem: SandboxFilesystemConfig;
}

export interface SandboxConfigPaths {
  globalBasePath: string;
  globalModePath?: string;
  projectBasePath: string;
  projectModePath?: string;
  projectGrantPath: string;
}

export interface LoadedSandboxPolicy {
  config: SandboxConfig;
  paths: SandboxConfigPaths;
  projectTrusted: boolean;
  warnings: string[];
  protectedWritePaths: string[];
}

export const DEFAULT_CONFIG: SandboxConfig = {
  policyVersion: 2,
  enabled: true,
  failClosed: true,
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
    readScope: "home",
    denyRead: [],
    allowRead: ["."],
    allowWrite: [".", "/tmp"],
    // V2 filesystem rules intentionally use portable literal/subtree paths.
    denyWrite: [".env"],
  },
};

const LEGACY_DEFAULT_CONFIG: SandboxConfig = {
  ...DEFAULT_CONFIG,
  policyVersion: 1,
  filesystem: {
    ...DEFAULT_CONFIG.filesystem,
    readScope: undefined,
    denyWrite: [".env", ".env.*", "*.pem", "*.key"],
  },
};

function mergeList(base?: string[], override?: string[]): string[] | undefined {
  if (!base && !override) return undefined;
  return [...new Set([...(base ?? []), ...(override ?? [])])];
}

export function deepMerge(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
  const result: SandboxConfig = { ...base, ...overrides, filesystem: { ...base.filesystem } };

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
      allowRead: mergeList(base.filesystem.allowRead, overrides.filesystem.allowRead) ?? [],
      denyRead: mergeList(base.filesystem.denyRead, overrides.filesystem.denyRead) ?? [],
      allowWrite: mergeList(base.filesystem.allowWrite, overrides.filesystem.allowWrite) ?? [],
      denyWrite: mergeList(base.filesystem.denyWrite, overrides.filesystem.denyWrite) ?? [],
    };
  }
  return result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertStringArray(value: unknown, field: string): asserts value is string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || !entry)) {
    throw new Error(`${field} must be an array of non-empty strings`);
  }
}

function hasUnsupportedV2Glob(pattern: string): boolean {
  const withoutSubtree = pattern.replace(/\/\*\*$/, "");
  return ["*", "?", "[", "]"].some((character) => withoutSubtree.includes(character));
}

export function validateConfig(
  value: unknown,
  source = "sandbox configuration",
): Partial<SandboxConfig> {
  if (!isRecord(value)) throw new Error(`${source}: expected a JSON object`);
  if (value.policyVersion !== undefined && value.policyVersion !== 1 && value.policyVersion !== 2) {
    throw new Error(`${source}: policyVersion must be 1 or 2`);
  }
  if (value.enabled !== undefined && typeof value.enabled !== "boolean") {
    throw new Error(`${source}: enabled must be boolean`);
  }
  if (value.failClosed !== undefined && typeof value.failClosed !== "boolean") {
    throw new Error(`${source}: failClosed must be boolean`);
  }
  if (value.failClosed === false) {
    throw new Error(`${source}: failClosed=false is not supported; use --no-sandbox explicitly`);
  }
  const filesystem = value.filesystem;
  if (filesystem !== undefined) {
    if (!isRecord(filesystem)) throw new Error(`${source}: filesystem must be an object`);
    for (const field of ["denyRead", "allowRead", "allowWrite", "denyWrite"] as const) {
      if (filesystem[field] !== undefined)
        assertStringArray(filesystem[field], `${source}: filesystem.${field}`);
    }
    if (
      filesystem.readScope !== undefined &&
      !["home", "strict", "open"].includes(String(filesystem.readScope))
    ) {
      throw new Error(`${source}: filesystem.readScope must be home, strict, or open`);
    }
    if (value.policyVersion === 2) {
      for (const field of ["denyRead", "allowRead", "allowWrite", "denyWrite"] as const) {
        const bad = Array.isArray(filesystem[field])
          ? (filesystem[field] as string[]).find(hasUnsupportedV2Glob)
          : undefined;
        if (bad) {
          throw new Error(
            `${source}: filesystem.${field} pattern "${bad}" is not portable in policyVersion 2`,
          );
        }
      }
    }
  }
  return value as Partial<SandboxConfig>;
}

function readJsonConfig(configPath: string): Partial<SandboxConfig> | undefined {
  if (!existsSync(configPath)) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(configPath, "utf-8"));
  } catch (error) {
    throw new Error(`Could not parse ${configPath}: ${error}`);
  }
  return validateConfig(parsed, configPath);
}

function modeSuffix(mode: string): string {
  return mode && mode !== "default" ? `.${mode}` : "";
}

function projectId(cwd: string): string {
  return createHash("sha256").update(canonicalizePath(cwd)).digest("hex").slice(0, 24);
}

export function getConfigPaths(cwd: string, mode = "default"): SandboxConfigPaths {
  const suffix = modeSuffix(mode);
  return {
    globalBasePath: join(getAgentDir(), "sandbox.json"),
    globalModePath: suffix ? join(getAgentDir(), `sandbox${suffix}.json`) : undefined,
    projectBasePath: join(cwd, ".pi", "sandbox.json"),
    projectModePath: suffix ? join(cwd, ".pi", `sandbox${suffix}.json`) : undefined,
    projectGrantPath: join(getAgentDir(), "sandbox-projects", `${projectId(cwd)}${suffix}.json`),
  };
}

function resolveSourcePath(pattern: string, base: string): string {
  if (pattern.startsWith("~")) return canonicalizePath(pattern);
  return canonicalizePath(isAbsolute(pattern) ? pattern : resolve(base, pattern));
}

function sanitizeProjectConfig(
  raw: Partial<SandboxConfig>,
  cwd: string,
  warnings: string[],
): Partial<SandboxConfig> {
  const root = canonicalizePath(cwd);
  const underRoot = (pattern: string): boolean => {
    const path = resolveSourcePath(pattern, cwd);
    return path === root || path.startsWith(root + "/");
  };
  const filterProjectAllows = (entries: string[] | undefined, field: string): string[] =>
    (entries ?? []).filter((entry) => {
      const keep = underRoot(entry);
      if (!keep) warnings.push(`Ignored project ${field} outside project root: ${entry}`);
      return keep;
    });

  const network = raw.network
    ? {
        allowedDomains: (raw.network.allowedDomains ?? []).filter((domain) => {
          if (domain !== "*") return true;
          warnings.push('Ignored project network.allowedDomains "*"; use trusted global config');
          return false;
        }),
        deniedDomains: raw.network.deniedDomains ?? [],
      }
    : undefined;
  const filesystem = raw.filesystem
    ? {
        denyRead: raw.filesystem.denyRead ?? [],
        allowRead: filterProjectAllows(raw.filesystem.allowRead, "allowRead"),
        allowWrite: filterProjectAllows(raw.filesystem.allowWrite, "allowWrite"),
        denyWrite: raw.filesystem.denyWrite ?? [],
      }
    : undefined;

  return { policyVersion: raw.policyVersion, network, filesystem } as Partial<SandboxConfig>;
}

function validateV2PortablePaths(config: SandboxConfig, source: string): void {
  if (config.policyVersion !== 2) return;
  for (const [field, patterns] of Object.entries({
    denyRead: config.filesystem.denyRead,
    allowRead: config.filesystem.allowRead ?? [],
    allowWrite: config.filesystem.allowWrite,
    denyWrite: config.filesystem.denyWrite,
  })) {
    const bad = patterns.find(hasUnsupportedV2Glob);
    if (bad) {
      throw new Error(
        `${source}: filesystem.${field} pattern "${bad}" is not portable in policyVersion 2; use a literal path or trailing /**`,
      );
    }
  }
}

export function loadPolicy(
  cwd: string,
  mode = "default",
  projectTrusted = false,
): LoadedSandboxPolicy {
  const paths = getConfigPaths(cwd, mode);
  const globalBase = readJsonConfig(paths.globalBasePath);
  const globalMode = paths.globalModePath ? readJsonConfig(paths.globalModePath) : undefined;
  const projectBase = projectTrusted ? readJsonConfig(paths.projectBasePath) : undefined;
  const projectMode =
    projectTrusted && paths.projectModePath ? readJsonConfig(paths.projectModePath) : undefined;
  const projectGrant = readJsonConfig(paths.projectGrantPath);
  const sources = [globalBase, globalMode, projectBase, projectMode, projectGrant].filter(
    (entry): entry is Partial<SandboxConfig> => entry !== undefined,
  );
  const explicitV2 = sources.some((entry) => entry.policyVersion === 2);
  const legacy = sources.length > 0 && !explicitV2;
  let config: SandboxConfig = structuredClone(legacy ? LEGACY_DEFAULT_CONFIG : DEFAULT_CONFIG);
  const warnings: string[] = [];
  for (const source of [globalBase, globalMode]) if (source) config = deepMerge(config, source);
  for (const source of [projectBase, projectMode]) {
    if (source) config = deepMerge(config, sanitizeProjectConfig(source, cwd, warnings));
  }
  if (projectGrant) config = deepMerge(config, projectGrant);
  config.policyVersion = legacy ? 1 : 2;
  if (config.policyVersion === 2) config.filesystem.readScope ??= "home";
  validateV2PortablePaths(config, "effective sandbox policy");

  const protectedWritePaths = [
    paths.globalBasePath,
    ...(paths.globalModePath ? [paths.globalModePath] : []),
    paths.projectBasePath,
    ...(paths.projectModePath ? [paths.projectModePath] : []),
    paths.projectGrantPath,
  ].map((path) => canonicalizePath(path));
  return { config, paths, projectTrusted, warnings, protectedWritePaths };
}

/** Compatibility helper. New extension code should retain a loadPolicy snapshot. */
export function loadConfig(cwd: string, mode = "default", projectTrusted = true): SandboxConfig {
  return loadPolicy(cwd, mode, projectTrusted).config;
}

function writeConfigFile(configPath: string, config: Partial<SandboxConfig>): void {
  mkdirSync(dirname(configPath), { recursive: true, mode: 0o700 });
  if (existsSync(configPath) && lstatSync(configPath).isSymbolicLink()) {
    throw new Error(`Refusing to write symlinked sandbox policy: ${configPath}`);
  }
  const temporary = join(dirname(configPath), `.${randomUUID()}.sandbox.tmp`);
  try {
    writeFileSync(temporary, JSON.stringify(config, null, 2) + "\n", {
      encoding: "utf-8",
      mode: 0o600,
      flag: "wx",
    });
    renameSync(temporary, configPath);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function readWritableConfig(configPath: string, policyVersion: 1 | 2): Partial<SandboxConfig> {
  return readJsonConfig(configPath) ?? { policyVersion };
}

export function addDomainToConfig(
  configPath: string,
  domain: string,
  policyVersion: 1 | 2 = 2,
): void {
  const config = readWritableConfig(configPath, policyVersion);
  const existing = config.network?.allowedDomains ?? [];
  if (existing.includes(domain)) return;
  config.network = {
    ...config.network,
    allowedDomains: [...existing, domain],
    deniedDomains: config.network?.deniedDomains ?? [],
  };
  writeConfigFile(configPath, config);
}

export function addReadPathToConfig(
  configPath: string,
  pathToAdd: string,
  policyVersion: 1 | 2 = 2,
): void {
  const config = readWritableConfig(configPath, policyVersion);
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

export function addWritePathToConfig(
  configPath: string,
  pathToAdd: string,
  policyVersion: 1 | 2 = 2,
): void {
  const config = readWritableConfig(configPath, policyVersion);
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
