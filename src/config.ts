import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join } from "node:path";

import { type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { CONFIG_DIR_NAME, getAgentDir } from "@earendil-works/pi-coding-agent";

import {
  type NormalizedProjectAccessRequests,
  type ProjectAccessRequests,
  type ProjectRequestApproval,
  type ProjectRequestSelection,
  type ProjectRequestSourceKind,
  normalizeProjectAccessRequests,
  projectRequestManifestHash,
} from "./access-requests.ts";
import {
  DEFAULT_MODE,
  getLegacyModePolicy,
  type ModePolicy,
  parseModePolicy,
  validateModeName,
} from "./modes.ts";
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
  policyVersion?: 2 | 3;
  enabled?: boolean;
  failClosed?: boolean;
  filesystem: SandboxFilesystemConfig;
}

type SandboxNetworkConfig = NonNullable<SandboxConfig["network"]>;

export type SandboxPolicyDocument = Omit<Partial<SandboxConfig>, "network" | "filesystem"> & {
  network?: Partial<SandboxNetworkConfig>;
  filesystem?: Partial<SandboxFilesystemConfig>;
  mode?: ModePolicy;
};

export interface SandboxConfigPaths {
  globalBasePath: string;
  globalModePath?: string;
  projectBasePath: string;
  projectModePath?: string;
  projectGrantPath: string;
  projectRequestApprovalPath: string;
}

export type ConfigFileState = "loaded" | "not-found" | "not-trusted" | "not-applicable";

export interface LoadedSandboxPolicy {
  policyVersion: 2 | 3;
  modeName: string;
  modePolicy: ModePolicy;
  modePolicySource: string;
  loadedConfigPaths: string[];
  configFileStates: {
    globalBase: ConfigFileState;
    globalMode: ConfigFileState;
    projectBase: ConfigFileState;
    projectMode: ConfigFileState;
    projectGrant: ConfigFileState;
    projectRequestApproval: ConfigFileState;
  };
  config: SandboxConfig;
  directConfig: SandboxConfig;
  reactiveProjectGrant?: SandboxPolicyDocument;
  paths: SandboxConfigPaths;
  projectRoot: string;
  projectTrusted: boolean;
  projectRequests: NormalizedProjectAccessRequests;
  projectRequestApproval?: ProjectRequestApproval;
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
    // Filesystem rules intentionally use portable literal/subtree paths.
    denyWrite: [".env"],
  },
};

function mergeList(base?: string[], override?: string[]): string[] | undefined {
  if (!base && !override) return undefined;
  return [...new Set([...(base ?? []), ...(override ?? [])])];
}

export function deepMerge(base: SandboxConfig, overrides: SandboxPolicyDocument): SandboxConfig {
  const { mode: _mode, ...configOverrides } = overrides;
  const result = {
    ...base,
    ...configOverrides,
    filesystem: { ...base.filesystem },
  } as SandboxConfig;

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

export function applyGlobalModeProfile(
  base: SandboxConfig,
  profile: SandboxPolicyDocument,
): SandboxConfig {
  const { mode: _mode, ...configOverrides } = profile;
  const result = {
    ...base,
    ...configOverrides,
    filesystem: { ...base.filesystem },
  } as SandboxConfig;
  if (profile.network) {
    result.network = {
      ...base.network,
      ...profile.network,
      allowedDomains:
        profile.network.allowedDomains === undefined
          ? [...(base.network?.allowedDomains ?? [])]
          : [...new Set(profile.network.allowedDomains)],
      deniedDomains: mergeList(base.network?.deniedDomains, profile.network.deniedDomains) ?? [],
    };
  }
  if (profile.filesystem) {
    result.filesystem = {
      ...base.filesystem,
      ...profile.filesystem,
      allowRead:
        profile.filesystem.allowRead === undefined
          ? [...(base.filesystem.allowRead ?? [])]
          : [...new Set(profile.filesystem.allowRead)],
      allowWrite:
        profile.filesystem.allowWrite === undefined
          ? [...base.filesystem.allowWrite]
          : [...new Set(profile.filesystem.allowWrite)],
      denyRead: mergeList(base.filesystem.denyRead, profile.filesystem.denyRead) ?? [],
      denyWrite: mergeList(base.filesystem.denyWrite, profile.filesystem.denyWrite) ?? [],
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

function hasUnsupportedFilesystemGlob(pattern: string): boolean {
  const withoutSubtree = pattern.replace(/\/\*\*$/, "");
  return ["*", "?", "[", "]"].some((character) => withoutSubtree.includes(character));
}

function assertDomainPattern(pattern: string, field: string): void {
  const host = pattern.startsWith("*.") ? pattern.slice(2) : pattern;
  if (
    pattern !== "*" &&
    (!host ||
      host.includes("*") ||
      host.includes("/") ||
      !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(host))
  ) {
    throw new Error(`${field} contains unsupported domain pattern "${pattern}"`);
  }
}

export function validateConfig(
  value: unknown,
  source = "sandbox configuration",
  validateMode = true,
): SandboxPolicyDocument {
  if (!isRecord(value)) throw new Error(`${source}: expected a JSON object`);
  if (value.policyVersion !== undefined && value.policyVersion !== 2 && value.policyVersion !== 3) {
    throw new Error(`${source}: policyVersion must be 2 or 3`);
  }
  if (validateMode && value.mode !== undefined) parseModePolicy(value.mode, source);
  if (value.enabled !== undefined && typeof value.enabled !== "boolean") {
    throw new Error(`${source}: enabled must be boolean`);
  }
  if (value.failClosed !== undefined && typeof value.failClosed !== "boolean") {
    throw new Error(`${source}: failClosed must be boolean`);
  }
  if (value.failClosed === false) {
    throw new Error(`${source}: failClosed=false is not supported; use --no-sandbox explicitly`);
  }
  const network = value.network;
  if (network !== undefined) {
    if (!isRecord(network)) throw new Error(`${source}: network must be an object`);
    for (const field of ["allowedDomains", "deniedDomains"] as const) {
      if (network[field] !== undefined) {
        assertStringArray(network[field], `${source}: network.${field}`);
        for (const pattern of network[field]) {
          assertDomainPattern(pattern, `${source}: network.${field}`);
        }
      }
    }
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
    for (const field of ["denyRead", "allowRead", "allowWrite", "denyWrite"] as const) {
      const bad = Array.isArray(filesystem[field])
        ? (filesystem[field] as string[]).find(hasUnsupportedFilesystemGlob)
        : undefined;
      if (bad) {
        throw new Error(
          `${source}: filesystem.${field} pattern "${bad}" is not portable; use a literal path or trailing /**`,
        );
      }
    }
  }
  return value as SandboxPolicyDocument;
}

function readJsonConfig(
  configPath: string,
  validateMode = true,
): SandboxPolicyDocument | undefined {
  if (!existsSync(configPath)) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(configPath, "utf-8"));
  } catch (error) {
    throw new Error(`Could not parse ${configPath}: ${error}`);
  }
  return validateConfig(parsed, configPath, validateMode);
}

function modeSuffix(mode: string): string {
  return mode && mode !== "default" ? `.${mode}` : "";
}

function projectId(cwd: string): string {
  return createHash("sha256").update(canonicalizePath(cwd)).digest("hex").slice(0, 24);
}

export function getConfigPaths(cwd: string, mode = DEFAULT_MODE): SandboxConfigPaths {
  validateModeName(mode);
  const suffix = modeSuffix(mode);
  const id = projectId(cwd);
  return {
    globalBasePath: join(getAgentDir(), "sandbox.json"),
    globalModePath: suffix ? join(getAgentDir(), `sandbox${suffix}.json`) : undefined,
    projectBasePath: join(cwd, CONFIG_DIR_NAME, "sandbox.json"),
    projectModePath: suffix ? join(cwd, CONFIG_DIR_NAME, `sandbox${suffix}.json`) : undefined,
    projectGrantPath: join(getAgentDir(), "sandbox-projects", `${id}${suffix}.json`),
    projectRequestApprovalPath: join(
      getAgentDir(),
      "sandbox-projects",
      `${id}${suffix}.requests.json`,
    ),
  };
}

export function listGlobalSandboxModes(): string[] {
  const modes = new Set<string>([DEFAULT_MODE]);
  try {
    for (const name of readdirSync(getAgentDir())) {
      const match = name.match(/^sandbox\.([a-z0-9][a-z0-9_-]*)\.json$/);
      if (match) modes.add(match[1]);
    }
  } catch {
    // The built-in default remains available before the agent directory exists.
  }
  return [DEFAULT_MODE, ...[...modes].filter((mode) => mode !== DEFAULT_MODE).sort()];
}

function declarations(
  values: string[] | undefined,
  sourcePath: string,
  sourceKind: ProjectRequestSourceKind,
) {
  return (values ?? []).map((value) => ({ value, sourcePath, sourceKind }));
}

export function splitProjectConfig(
  raw: SandboxPolicyDocument,
  sourcePath: string,
  sourceKind: ProjectRequestSourceKind,
  warnings: string[],
): { restrictions: SandboxPolicyDocument; requests: ProjectAccessRequests } {
  if (raw.network?.allowedDomains?.includes("*")) {
    throw new Error(`${sourcePath}: project network.allowedDomains cannot contain "*"`);
  }
  const ignored = Object.keys(raw).filter(
    (field) => !["policyVersion", "network", "filesystem"].includes(field),
  );
  for (const field of Object.keys(raw.network ?? {})) {
    if (!["allowedDomains", "deniedDomains"].includes(field)) ignored.push(`network.${field}`);
  }
  for (const field of Object.keys(raw.filesystem ?? {})) {
    if (!["denyRead", "allowRead", "allowWrite", "denyWrite"].includes(field)) {
      ignored.push(`filesystem.${field}`);
    }
  }
  if (ignored.length) {
    warnings.push(`Ignored unsupported project controls: ${ignored.sort().join(", ")}`);
  }

  return {
    restrictions: {
      policyVersion: 2,
      network: {
        allowedDomains: [],
        deniedDomains: raw.network?.deniedDomains ?? [],
      },
      filesystem: {
        denyRead: raw.filesystem?.denyRead ?? [],
        allowRead: [],
        allowWrite: [],
        denyWrite: raw.filesystem?.denyWrite ?? [],
      },
    },
    requests: {
      readPaths: declarations(raw.filesystem?.allowRead, sourcePath, sourceKind),
      writePaths: declarations(raw.filesystem?.allowWrite, sourcePath, sourceKind),
      domains: declarations(raw.network?.allowedDomains, sourcePath, sourceKind),
    },
  };
}

function combineRequests(parts: ProjectAccessRequests[]): ProjectAccessRequests {
  return {
    readPaths: parts.flatMap((part) => part.readPaths),
    writePaths: parts.flatMap((part) => part.writePaths),
    domains: parts.flatMap((part) => part.domains),
  };
}

function validatePortablePaths(config: SandboxConfig, source: string): void {
  for (const [field, patterns] of Object.entries({
    denyRead: config.filesystem.denyRead,
    allowRead: config.filesystem.allowRead ?? [],
    allowWrite: config.filesystem.allowWrite,
    denyWrite: config.filesystem.denyWrite,
  })) {
    const bad = patterns.find(hasUnsupportedFilesystemGlob);
    if (bad) {
      throw new Error(
        `${source}: filesystem.${field} pattern "${bad}" is not portable; use a literal path or trailing /**`,
      );
    }
  }
}

function parseApproval(value: unknown, source: string): ProjectRequestApproval {
  if (!isRecord(value) || value.policyVersion !== 2) {
    throw new Error(`${source}: expected a policyVersion 2 approval object`);
  }
  for (const field of ["projectRoot", "mode", "manifestHash", "approvedAt"] as const) {
    if (typeof value[field] !== "string" || !value[field]) {
      throw new Error(`${source}: ${field} must be a non-empty string`);
    }
  }
  if (!isRecord(value.approved)) throw new Error(`${source}: approved must be an object`);
  for (const field of ["read", "write", "network"] as const) {
    assertStringArray(value.approved[field], `${source}: approved.${field}`);
  }
  for (const field of ["read", "write"] as const) {
    for (const path of value.approved[field] as string[]) {
      const subtree = path.endsWith("/**");
      const raw = subtree ? path.slice(0, -3) || "/" : path;
      if (!isAbsolute(raw) || hasUnsupportedFilesystemGlob(path)) {
        throw new Error(`${source}: approved.${field} paths must be canonical absolute paths`);
      }
      const canonical = canonicalizePath(raw);
      if (canonical !== raw) {
        throw new Error(`${source}: approved.${field} path is not canonical: ${path}`);
      }
    }
  }
  for (const domain of value.approved.network as string[]) {
    assertDomainPattern(domain, `${source}: approved.network`);
    if (domain === "*") throw new Error(`${source}: approved.network cannot contain "*"`);
  }
  if (!String(value.manifestHash).startsWith("sha256:")) {
    throw new Error(`${source}: manifestHash must use sha256`);
  }
  if (Number.isNaN(Date.parse(String(value.approvedAt)))) {
    throw new Error(`${source}: approvedAt must be an ISO timestamp`);
  }
  return value as unknown as ProjectRequestApproval;
}

export function readProjectRequestApproval(
  approvalPath: string,
  projectRoot: string,
  mode: string,
  warnings: string[],
): ProjectRequestApproval | undefined {
  if (!existsSync(approvalPath)) return undefined;
  try {
    if (existsSync(dirname(approvalPath))) {
      const directoryStat = lstatSync(dirname(approvalPath));
      if (directoryStat.isSymbolicLink()) throw new Error("approval directory is a symbolic link");
      if ((directoryStat.mode & 0o077) !== 0) {
        throw new Error("approval directory permissions must not grant group or other access");
      }
      if (process.getuid && directoryStat.uid !== process.getuid()) {
        throw new Error("approval directory is not owned by the current user");
      }
    }
    const approvalStat = lstatSync(approvalPath);
    if (approvalStat.isSymbolicLink()) throw new Error("approval path is a symbolic link");
    if ((approvalStat.mode & 0o077) !== 0) {
      throw new Error("approval file permissions must not grant group or other access");
    }
    if (process.getuid && approvalStat.uid !== process.getuid()) {
      throw new Error("approval file is not owned by the current user");
    }
    const approval = parseApproval(JSON.parse(readFileSync(approvalPath, "utf-8")), approvalPath);
    if (approval.projectRoot !== canonicalizePath(projectRoot)) {
      throw new Error("approval projectRoot does not match this project");
    }
    if (approval.mode !== mode) throw new Error("approval mode does not match the active mode");
    return approval;
  } catch (error) {
    warnings.push(`Ignored invalid project request approval ${approvalPath}: ${error}`);
    return undefined;
  }
}

function resolveModeBehavior(
  mode: string,
  globalBase: SandboxPolicyDocument | undefined,
  globalMode: SandboxPolicyDocument | undefined,
  paths: SandboxConfigPaths,
): { policy: ModePolicy; source: string; version: 2 | 3 } {
  if (mode === DEFAULT_MODE) {
    if (globalBase?.policyVersion === 3) {
      if (!globalBase.mode) {
        throw new Error(`${paths.globalBasePath}: policyVersion 3 requires an explicit mode block`);
      }
      return {
        policy: parseModePolicy(globalBase.mode, paths.globalBasePath),
        source: paths.globalBasePath,
        version: 3,
      };
    }
    return {
      policy: getLegacyModePolicy(DEFAULT_MODE)!,
      source: "<built-in:v2-default>",
      version: 2,
    };
  }

  if (globalMode?.policyVersion === 3) {
    if (!globalMode.mode) {
      throw new Error(`${paths.globalModePath}: policyVersion 3 requires an explicit mode block`);
    }
    return {
      policy: parseModePolicy(globalMode.mode, paths.globalModePath ?? "global mode policy"),
      source: paths.globalModePath ?? "global mode policy",
      version: 3,
    };
  }

  const legacy = getLegacyModePolicy(mode);
  if (legacy && globalBase?.policyVersion !== 3) {
    return { policy: legacy, source: `<built-in:v2-${mode}>`, version: 2 };
  }
  if (!globalMode) {
    throw new Error(
      `Sandbox mode "${mode}" is not defined; create ${paths.globalModePath} with policyVersion 3 and an explicit mode block`,
    );
  }
  throw new Error(
    `Custom mode "${mode}" requires policyVersion 3 and an explicit mode block in ${paths.globalModePath}`,
  );
}

export function loadPolicy(
  cwd: string,
  mode = DEFAULT_MODE,
  projectTrusted = false,
): LoadedSandboxPolicy {
  validateModeName(mode);
  const projectRoot = canonicalizePath(cwd);
  const paths = getConfigPaths(projectRoot, mode);
  const globalBase = readJsonConfig(paths.globalBasePath);
  const globalMode = paths.globalModePath ? readJsonConfig(paths.globalModePath) : undefined;
  const projectBase = projectTrusted ? readJsonConfig(paths.projectBasePath, false) : undefined;
  const projectMode =
    projectTrusted && paths.projectModePath
      ? readJsonConfig(paths.projectModePath, false)
      : undefined;
  const projectGrant = readJsonConfig(paths.projectGrantPath);
  const modeBehavior = resolveModeBehavior(mode, globalBase, globalMode, paths);
  const policyVersion: 2 | 3 =
    modeBehavior.version === 3 || globalBase?.policyVersion === 3 ? 3 : 2;
  let config: SandboxConfig = structuredClone(DEFAULT_CONFIG);
  const warnings: string[] = [];
  if (globalBase) {
    config =
      globalBase.policyVersion === 3
        ? applyGlobalModeProfile(config, globalBase)
        : deepMerge(config, globalBase);
  }
  if (globalMode) {
    config =
      globalMode.policyVersion === 3
        ? applyGlobalModeProfile(config, globalMode)
        : deepMerge(config, globalMode);
  }

  const projectParts: ProjectAccessRequests[] = [];
  if (projectBase) {
    const split = splitProjectConfig(projectBase, paths.projectBasePath, "project-base", warnings);
    config = deepMerge(config, split.restrictions);
    projectParts.push(split.requests);
  }
  if (projectMode && paths.projectModePath) {
    const split = splitProjectConfig(projectMode, paths.projectModePath, "project-mode", warnings);
    config = deepMerge(config, split.restrictions);
    projectParts.push(split.requests);
  }
  config.policyVersion = policyVersion;
  config.filesystem.readScope ??= "home";
  const directConfig = structuredClone(config);
  if (projectGrant) config = deepMerge(config, projectGrant);
  config.policyVersion = policyVersion;
  config.filesystem.readScope ??= "home";
  validatePortablePaths(config, "effective sandbox policy");

  const projectRequests = normalizeProjectAccessRequests(
    combineRequests(projectParts),
    projectRoot,
  );
  const projectRequestApproval = projectTrusted
    ? readProjectRequestApproval(paths.projectRequestApprovalPath, projectRoot, mode, warnings)
    : undefined;
  const protectedWritePaths = [
    paths.globalBasePath,
    ...(paths.globalModePath ? [paths.globalModePath] : []),
    paths.projectBasePath,
    ...(paths.projectModePath ? [paths.projectModePath] : []),
    paths.projectGrantPath,
    paths.projectRequestApprovalPath,
  ].map((path) => canonicalizePath(path));
  const loadedConfigPaths = [
    ...(globalBase ? [paths.globalBasePath] : []),
    ...(globalMode && paths.globalModePath ? [paths.globalModePath] : []),
    ...(projectBase ? [paths.projectBasePath] : []),
    ...(projectMode && paths.projectModePath ? [paths.projectModePath] : []),
    ...(projectGrant ? [paths.projectGrantPath] : []),
    ...(projectRequestApproval ? [paths.projectRequestApprovalPath] : []),
  ];
  return {
    policyVersion,
    modeName: mode,
    modePolicy: modeBehavior.policy,
    modePolicySource: modeBehavior.source,
    loadedConfigPaths,
    configFileStates: {
      globalBase: globalBase ? "loaded" : "not-found",
      globalMode: paths.globalModePath ? (globalMode ? "loaded" : "not-found") : "not-applicable",
      projectBase: !projectTrusted ? "not-trusted" : projectBase ? "loaded" : "not-found",
      projectMode: !paths.projectModePath
        ? "not-applicable"
        : !projectTrusted
          ? "not-trusted"
          : projectMode
            ? "loaded"
            : "not-found",
      projectGrant: projectGrant ? "loaded" : "not-found",
      projectRequestApproval: !projectTrusted
        ? "not-trusted"
        : projectRequestApproval
          ? "loaded"
          : "not-found",
    },
    config,
    directConfig,
    reactiveProjectGrant: projectGrant,
    paths,
    projectRoot,
    projectTrusted,
    projectRequests,
    projectRequestApproval,
    warnings,
    protectedWritePaths,
  };
}

/** Compatibility helper. New extension code should retain a loadPolicy snapshot. */
export function loadConfig(cwd: string, mode = "default", projectTrusted = true): SandboxConfig {
  return loadPolicy(cwd, mode, projectTrusted).config;
}

function writeJsonFile(configPath: string, value: unknown): void {
  mkdirSync(dirname(configPath), { recursive: true, mode: 0o700 });
  if (existsSync(configPath) && lstatSync(configPath).isSymbolicLink()) {
    throw new Error(`Refusing to write symlinked sandbox policy: ${configPath}`);
  }
  const temporary = join(dirname(configPath), `.${randomUUID()}.sandbox.tmp`);
  try {
    writeFileSync(temporary, JSON.stringify(value, null, 2) + "\n", {
      encoding: "utf-8",
      mode: 0o600,
      flag: "wx",
    });
    renameSync(temporary, configPath);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function readWritableConfig(configPath: string): SandboxPolicyDocument {
  return readJsonConfig(configPath) ?? { policyVersion: 2 };
}

export function writeProjectRequestApproval(
  approvalPath: string,
  projectRoot: string,
  mode: string,
  requests: NormalizedProjectAccessRequests,
  approved: ProjectRequestSelection,
): ProjectRequestApproval {
  if (existsSync(dirname(approvalPath)) && lstatSync(dirname(approvalPath)).isSymbolicLink()) {
    throw new Error(`Refusing to write symlinked approval directory: ${dirname(approvalPath)}`);
  }
  mkdirSync(dirname(approvalPath), { recursive: true, mode: 0o700 });
  const directoryStat = lstatSync(dirname(approvalPath));
  if (process.getuid && directoryStat.uid !== process.getuid()) {
    throw new Error(`Refusing to write approval directory not owned by the current user`);
  }
  chmodSync(dirname(approvalPath), 0o700);
  const approval: ProjectRequestApproval = {
    policyVersion: 2,
    projectRoot: canonicalizePath(projectRoot),
    mode,
    manifestHash: projectRequestManifestHash(requests, projectRoot, mode),
    approvedAt: new Date().toISOString(),
    approved: {
      read: [...new Set(approved.read)].sort(),
      write: [...new Set(approved.write)].sort(),
      network: [...new Set(approved.network)].sort(),
    },
  };
  writeJsonFile(approvalPath, approval);
  return approval;
}

export function addDomainToConfig(configPath: string, domain: string): void {
  const config = readWritableConfig(configPath);
  const existing = config.network?.allowedDomains ?? [];
  if (existing.includes(domain)) return;
  config.network = {
    ...config.network,
    allowedDomains: [...existing, domain],
    deniedDomains: config.network?.deniedDomains ?? [],
  };
  writeJsonFile(configPath, config);
}

export function addReadPathToConfig(configPath: string, pathToAdd: string): void {
  const config = readWritableConfig(configPath);
  const existing = config.filesystem?.allowRead ?? [];
  if (existing.includes(pathToAdd)) return;
  config.filesystem = {
    ...config.filesystem,
    allowRead: [...existing, pathToAdd],
    denyRead: config.filesystem?.denyRead ?? [],
    allowWrite: config.filesystem?.allowWrite ?? [],
    denyWrite: config.filesystem?.denyWrite ?? [],
  };
  writeJsonFile(configPath, config);
}

export function addWritePathToConfig(configPath: string, pathToAdd: string): void {
  const config = readWritableConfig(configPath);
  const existing = config.filesystem?.allowWrite ?? [];
  if (existing.includes(pathToAdd)) return;
  config.filesystem = {
    ...config.filesystem,
    allowWrite: [...existing, pathToAdd],
    denyRead: config.filesystem?.denyRead ?? [],
    denyWrite: config.filesystem?.denyWrite ?? [],
  };
  writeJsonFile(configPath, config);
}
