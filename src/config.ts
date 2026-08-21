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
  type CategoricalDenies,
  DEFAULT_MODE,
  DEFAULT_OTHERWISE_POLICY,
  getLegacyCategoricalDenies,
  getLegacyModePolicy,
  NO_CATEGORICAL_DENIES,
  type OtherwisePolicy,
  parseOtherwiseAction,
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
  /** Normalized from v3 per-capability `otherwise` fields; never written as a top-level field. */
  otherwise?: Partial<OtherwisePolicy>;
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
  otherwisePolicy: OtherwisePolicy;
  otherwisePolicySources: Record<keyof OtherwisePolicy, string>;
  /** Only preserves categorical built-in v2 behavior such as read-only mode. */
  legacyCategoricalDenies: CategoricalDenies;
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
  const { otherwise: _otherwise, ...configOverrides } = overrides;
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
  const { otherwise: _otherwise, ...configOverrides } = profile;
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

function validateCommonFields(value: Record<string, unknown>, source: string): void {
  if (value.enabled !== undefined && typeof value.enabled !== "boolean") {
    throw new Error(`${source}: enabled must be boolean`);
  }
  if (value.failClosed !== undefined && typeof value.failClosed !== "boolean") {
    throw new Error(`${source}: failClosed must be boolean`);
  }
  if (value.failClosed === false) {
    throw new Error(`${source}: failClosed=false is not supported; use --no-sandbox explicitly`);
  }
}

function validatePortableList(value: unknown, field: string): string[] | undefined {
  if (value === undefined) return undefined;
  assertStringArray(value, field);
  const bad = value.find(hasUnsupportedFilesystemGlob);
  if (bad) {
    throw new Error(
      `${field} pattern "${bad}" is not portable; use a literal path or trailing /**`,
    );
  }
  return value;
}

function validateDomainList(value: unknown, field: string): string[] | undefined {
  if (value === undefined) return undefined;
  assertStringArray(value, field);
  for (const pattern of value) assertDomainPattern(pattern, field);
  return value;
}

function validateV2Config(value: Record<string, unknown>, source: string): SandboxPolicyDocument {
  const network = value.network;
  if (network !== undefined) {
    if (!isRecord(network)) throw new Error(`${source}: network must be an object`);
    validateDomainList(network.allowedDomains, `${source}: network.allowedDomains`);
    validateDomainList(network.deniedDomains, `${source}: network.deniedDomains`);
  }
  const filesystem = value.filesystem;
  if (filesystem !== undefined) {
    if (!isRecord(filesystem)) throw new Error(`${source}: filesystem must be an object`);
    for (const field of ["denyRead", "allowRead", "allowWrite", "denyWrite"] as const) {
      validatePortableList(filesystem[field], `${source}: filesystem.${field}`);
    }
    if (
      filesystem.readScope !== undefined &&
      !["home", "strict", "open"].includes(String(filesystem.readScope))
    ) {
      throw new Error(`${source}: filesystem.readScope must be home, strict, or open`);
    }
  }
  return value as SandboxPolicyDocument;
}

function validateV3Capability(
  value: unknown,
  field: string,
  includeScope: boolean,
): {
  allow?: string[];
  deny?: string[];
  otherwise?: "prompt" | "deny";
  scope?: ReadScope;
} {
  if (!isRecord(value)) throw new Error(`${field} must be an object`);
  const supported = new Set(
    includeScope ? ["allow", "deny", "otherwise", "scope"] : ["allow", "deny", "otherwise"],
  );
  const unsupported = Object.keys(value).find((key) => !supported.has(key));
  if (unsupported) throw new Error(`${field}.${unsupported} is not supported`);
  const allow = validatePortableList(value.allow, `${field}.allow`);
  const deny = validatePortableList(value.deny, `${field}.deny`);
  const otherwise =
    value.otherwise === undefined
      ? undefined
      : parseOtherwiseAction(value.otherwise, `${field}.otherwise`);
  const scope = value.scope;
  if (scope !== undefined && !["home", "strict", "open"].includes(String(scope))) {
    throw new Error(`${field}.scope must be home, strict, or open`);
  }
  return { allow, deny, otherwise, scope: scope as ReadScope | undefined };
}

function validateV3Config(value: Record<string, unknown>, source: string): SandboxPolicyDocument {
  if (value.mode !== undefined) {
    throw new Error(
      `${source}: the inner mode block is no longer supported; use per-capability otherwise actions`,
    );
  }
  const normalized = { ...value } as Record<string, unknown>;
  const otherwise: Partial<OtherwisePolicy> = {};

  const network = value.network;
  if (network !== undefined) {
    if (!isRecord(network)) throw new Error(`${source}: network must be an object`);
    if (network.allowedDomains !== undefined) {
      throw new Error(`${source}: network.allowedDomains is v2 syntax; use network.allow`);
    }
    if (network.deniedDomains !== undefined) {
      throw new Error(`${source}: network.deniedDomains is v2 syntax; use network.deny`);
    }
    if (network.strictAllowlist !== undefined) {
      throw new Error(`${source}: network.strictAllowlist is replaced by network.otherwise`);
    }
    const allow = validateDomainList(network.allow, `${source}: network.allow`);
    const deny = validateDomainList(network.deny, `${source}: network.deny`);
    if (network.otherwise !== undefined) {
      otherwise.network = parseOtherwiseAction(network.otherwise, `${source}: network.otherwise`);
    }
    const { allow: _allow, deny: _deny, otherwise: _otherwise, ...runtimeNetwork } = network;
    normalized.network = {
      ...runtimeNetwork,
      ...(allow === undefined ? {} : { allowedDomains: allow }),
      ...(deny === undefined ? {} : { deniedDomains: deny }),
    };
  }

  const filesystem = value.filesystem;
  if (filesystem !== undefined) {
    if (!isRecord(filesystem)) throw new Error(`${source}: filesystem must be an object`);
    for (const oldField of ["readScope", "denyRead", "allowRead", "allowWrite", "denyWrite"]) {
      if (filesystem[oldField] !== undefined) {
        const replacement =
          oldField === "readScope"
            ? "filesystem.read.scope"
            : oldField.endsWith("Read")
              ? `filesystem.read.${oldField.startsWith("allow") ? "allow" : "deny"}`
              : `filesystem.write.${oldField.startsWith("allow") ? "allow" : "deny"}`;
        throw new Error(`${source}: filesystem.${oldField} is v2 syntax; use ${replacement}`);
      }
    }
    const read =
      filesystem.read === undefined
        ? undefined
        : validateV3Capability(filesystem.read, `${source}: filesystem.read`, true);
    const write =
      filesystem.write === undefined
        ? undefined
        : validateV3Capability(filesystem.write, `${source}: filesystem.write`, false);
    if (read?.otherwise !== undefined) otherwise.read = read.otherwise;
    if (write?.otherwise !== undefined) otherwise.write = write.otherwise;
    const { read: _read, write: _write, ...runtimeFilesystem } = filesystem;
    normalized.filesystem = {
      ...runtimeFilesystem,
      ...(read?.scope === undefined ? {} : { readScope: read.scope }),
      ...(read?.allow === undefined ? {} : { allowRead: read.allow }),
      ...(read?.deny === undefined ? {} : { denyRead: read.deny }),
      ...(write?.allow === undefined ? {} : { allowWrite: write.allow }),
      ...(write?.deny === undefined ? {} : { denyWrite: write.deny }),
    };
  }
  normalized.otherwise = otherwise;
  return normalized as SandboxPolicyDocument;
}

export function validateConfig(
  value: unknown,
  source = "sandbox configuration",
): SandboxPolicyDocument {
  if (!isRecord(value)) throw new Error(`${source}: expected a JSON object`);
  if (value.policyVersion !== undefined && value.policyVersion !== 2 && value.policyVersion !== 3) {
    throw new Error(`${source}: policyVersion must be 2 or 3`);
  }
  validateCommonFields(value, source);
  return value.policyVersion === 3
    ? validateV3Config(value, source)
    : validateV2Config(value, source);
}

function readJsonConfig(configPath: string): SandboxPolicyDocument | undefined {
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
    (field) => !["policyVersion", "network", "filesystem", "otherwise"].includes(field),
  );
  if (raw.otherwise?.read !== undefined) ignored.push("filesystem.read.otherwise");
  if (raw.otherwise?.write !== undefined) ignored.push("filesystem.write.otherwise");
  if (raw.otherwise?.network !== undefined) ignored.push("network.otherwise");
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

function resolveOtherwisePolicy(
  mode: string,
  globalBase: SandboxPolicyDocument | undefined,
  globalMode: SandboxPolicyDocument | undefined,
  paths: SandboxConfigPaths,
): {
  policy: OtherwisePolicy;
  sources: Record<keyof OtherwisePolicy, string>;
  legacyCategoricalDenies: CategoricalDenies;
  version: 2 | 3;
} {
  const legacy = getLegacyModePolicy(mode);
  if (mode !== DEFAULT_MODE && !globalMode && (!legacy || globalBase?.policyVersion === 3)) {
    throw new Error(
      `Sandbox mode "${mode}" is not defined; create ${paths.globalModePath} with policyVersion 3`,
    );
  }
  if (
    mode !== DEFAULT_MODE &&
    globalMode &&
    globalMode.policyVersion !== 3 &&
    (!legacy || globalBase?.policyVersion === 3)
  ) {
    throw new Error(`Custom mode "${mode}" requires policyVersion 3 in ${paths.globalModePath}`);
  }

  const initial =
    globalBase?.policyVersion === 3 || globalMode?.policyVersion === 3
      ? DEFAULT_OTHERWISE_POLICY
      : (legacy ?? DEFAULT_OTHERWISE_POLICY);
  const initialSource =
    globalBase?.policyVersion === 3 || globalMode?.policyVersion === 3
      ? "<built-in:v3-default>"
      : `<built-in:v2-${legacy ? mode : DEFAULT_MODE}>`;
  const policy = { ...initial };
  const sources: Record<keyof OtherwisePolicy, string> = {
    read: initialSource,
    write: initialSource,
    network: initialSource,
  };

  if (globalBase?.policyVersion === 3) {
    for (const capability of ["read", "write", "network"] as const) {
      const action = globalBase.otherwise?.[capability];
      if (!action) {
        const field =
          capability === "network" ? "network.otherwise" : `filesystem.${capability}.otherwise`;
        throw new Error(`${paths.globalBasePath}: policyVersion 3 requires explicit ${field}`);
      }
      policy[capability] = action;
      sources[capability] = paths.globalBasePath;
    }
  }

  if (globalMode?.policyVersion === 3) {
    for (const capability of ["read", "write", "network"] as const) {
      const action = globalMode.otherwise?.[capability];
      if (action) {
        policy[capability] = action;
        sources[capability] = paths.globalModePath ?? "global mode policy";
      }
    }
  }

  const usesV3 = globalBase?.policyVersion === 3 || globalMode?.policyVersion === 3;
  return {
    policy,
    sources,
    legacyCategoricalDenies: usesV3
      ? { ...NO_CATEGORICAL_DENIES }
      : getLegacyCategoricalDenies(mode),
    version: usesV3 ? 3 : 2,
  };
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
  const projectBase = projectTrusted ? readJsonConfig(paths.projectBasePath) : undefined;
  const projectMode =
    projectTrusted && paths.projectModePath ? readJsonConfig(paths.projectModePath) : undefined;
  const projectGrant = readJsonConfig(paths.projectGrantPath);
  const otherwiseResolution = resolveOtherwisePolicy(mode, globalBase, globalMode, paths);
  const policyVersion = otherwiseResolution.version;
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
    otherwisePolicy: otherwiseResolution.policy,
    otherwisePolicySources: otherwiseResolution.sources,
    legacyCategoricalDenies: otherwiseResolution.legacyCategoricalDenies,
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

function readWritableConfig(configPath: string): Record<string, unknown> {
  if (!existsSync(configPath)) return { policyVersion: 2 };
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(configPath, "utf-8"));
  } catch (error) {
    throw new Error(`Could not parse ${configPath}: ${error}`);
  }
  validateConfig(parsed, configPath);
  if (!isRecord(parsed)) throw new Error(`${configPath}: expected a JSON object`);
  return parsed;
}

function writableStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
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
  const network = isRecord(config.network) ? config.network : {};
  const field = config.policyVersion === 3 ? "allow" : "allowedDomains";
  const existing = writableStringArray(network[field]);
  if (existing.includes(domain)) return;
  config.network = {
    ...network,
    [field]: [...existing, domain],
    ...(config.policyVersion === 3
      ? {}
      : { deniedDomains: writableStringArray(network.deniedDomains) }),
  };
  validateConfig(config, configPath);
  writeJsonFile(configPath, config);
}

export function addReadPathToConfig(configPath: string, pathToAdd: string): void {
  const config = readWritableConfig(configPath);
  const filesystem = isRecord(config.filesystem) ? config.filesystem : {};
  if (config.policyVersion === 3) {
    const read = isRecord(filesystem.read) ? filesystem.read : {};
    const existing = writableStringArray(read.allow);
    if (existing.includes(pathToAdd)) return;
    config.filesystem = { ...filesystem, read: { ...read, allow: [...existing, pathToAdd] } };
  } else {
    const existing = writableStringArray(filesystem.allowRead);
    if (existing.includes(pathToAdd)) return;
    config.filesystem = {
      ...filesystem,
      allowRead: [...existing, pathToAdd],
      denyRead: writableStringArray(filesystem.denyRead),
      allowWrite: writableStringArray(filesystem.allowWrite),
      denyWrite: writableStringArray(filesystem.denyWrite),
    };
  }
  validateConfig(config, configPath);
  writeJsonFile(configPath, config);
}

export function addWritePathToConfig(configPath: string, pathToAdd: string): void {
  const config = readWritableConfig(configPath);
  const filesystem = isRecord(config.filesystem) ? config.filesystem : {};
  if (config.policyVersion === 3) {
    const write = isRecord(filesystem.write) ? filesystem.write : {};
    const existing = writableStringArray(write.allow);
    if (existing.includes(pathToAdd)) return;
    config.filesystem = { ...filesystem, write: { ...write, allow: [...existing, pathToAdd] } };
  } else {
    const existing = writableStringArray(filesystem.allowWrite);
    if (existing.includes(pathToAdd)) return;
    config.filesystem = {
      ...filesystem,
      allowWrite: [...existing, pathToAdd],
      denyRead: writableStringArray(filesystem.denyRead),
      denyWrite: writableStringArray(filesystem.denyWrite),
    };
  }
  validateConfig(config, configPath);
  writeJsonFile(configPath, config);
}
