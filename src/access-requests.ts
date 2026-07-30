import { createHash } from "node:crypto";

import { type SandboxConfig } from "./config.ts";
import { type ModePolicy } from "./modes.ts";
import {
  canonicalizePath,
  domainMatchesPattern,
  evaluateReadPolicy,
  matchesPattern,
  resolvePolicyPatterns,
} from "./policy.ts";

export type ProjectRequestSourceKind = "project-base" | "project-mode";

export interface ProjectRequestDeclaration {
  value: string;
  sourcePath: string;
  sourceKind: ProjectRequestSourceKind;
}

export interface ProjectAccessRequests {
  readPaths: ProjectRequestDeclaration[];
  writePaths: ProjectRequestDeclaration[];
  domains: ProjectRequestDeclaration[];
}

export interface ProjectRequestSource {
  sourcePath: string;
  sourceKind: ProjectRequestSourceKind;
}

export interface NormalizedPathRequest {
  configuredValues: string[];
  canonicalPath: string;
  sources: ProjectRequestSource[];
}

export interface NormalizedDomainRequest {
  configuredValues: string[];
  domain: string;
  sources: ProjectRequestSource[];
}

export interface NormalizedProjectAccessRequests {
  readPaths: NormalizedPathRequest[];
  writePaths: NormalizedPathRequest[];
  domains: NormalizedDomainRequest[];
}

export type RequestStatus =
  | "hard-denied"
  | "mode-denied"
  | "already-allowed"
  | "previously-approved"
  | "pending";

export interface ClassifiedPathRequest extends NormalizedPathRequest {
  status: RequestStatus;
}

export interface ClassifiedDomainRequest extends NormalizedDomainRequest {
  status: RequestStatus;
}

export interface ProjectRequestApproval {
  policyVersion: 2;
  projectRoot: string;
  mode: string;
  manifestHash: string;
  approvedAt: string;
  approved: {
    read: string[];
    write: string[];
    network: string[];
  };
}

export interface ProjectRequestState {
  requests: NormalizedProjectAccessRequests;
  readPaths: ClassifiedPathRequest[];
  writePaths: ClassifiedPathRequest[];
  domains: ClassifiedDomainRequest[];
  manifestHash: string;
  approval?: ProjectRequestApproval;
}

export interface DeclaredProjectAllowances {
  domains: string[];
  readPaths: string[];
  writePaths: string[];
}

export const EMPTY_PROJECT_REQUESTS: ProjectAccessRequests = {
  readPaths: [],
  writePaths: [],
  domains: [],
};

function uniqueSources(entries: ProjectRequestDeclaration[]): ProjectRequestSource[] {
  const seen = new Set<string>();
  const result: ProjectRequestSource[] = [];
  for (const entry of entries) {
    const key = `${entry.sourceKind}\0${entry.sourcePath}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({ sourcePath: entry.sourcePath, sourceKind: entry.sourceKind });
  }
  return result.sort((a, b) =>
    `${a.sourceKind}:${a.sourcePath}`.localeCompare(`${b.sourceKind}:${b.sourcePath}`),
  );
}

function normalizePathDeclarations(
  entries: ProjectRequestDeclaration[],
  projectRoot: string,
): NormalizedPathRequest[] {
  const grouped = new Map<string, ProjectRequestDeclaration[]>();
  for (const entry of entries) {
    const subtree = entry.value.endsWith("/**");
    const raw = subtree ? entry.value.slice(0, -3) || "/" : entry.value;
    const canonical = canonicalizePath(raw, projectRoot);
    const canonicalPath = subtree ? `${canonical === "/" ? "" : canonical}/**` : canonical;
    const existing = grouped.get(canonicalPath) ?? [];
    existing.push(entry);
    grouped.set(canonicalPath, existing);
  }
  return [...grouped.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([canonicalPath, declarations]) => ({
      canonicalPath,
      configuredValues: [...new Set(declarations.map((entry) => entry.value))].sort(),
      sources: uniqueSources(declarations),
    }));
}

function normalizeDomain(domain: string): string {
  return domain.toLowerCase().replace(/\.$/, "");
}

function normalizeDomainDeclarations(
  entries: ProjectRequestDeclaration[],
): NormalizedDomainRequest[] {
  const grouped = new Map<string, ProjectRequestDeclaration[]>();
  for (const entry of entries) {
    const domain = normalizeDomain(entry.value);
    const existing = grouped.get(domain) ?? [];
    existing.push(entry);
    grouped.set(domain, existing);
  }
  return [...grouped.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([domain, declarations]) => ({
      domain,
      configuredValues: [...new Set(declarations.map((entry) => entry.value))].sort(),
      sources: uniqueSources(declarations),
    }));
}

export function normalizeProjectAccessRequests(
  requests: ProjectAccessRequests,
  projectRoot: string,
): NormalizedProjectAccessRequests {
  return {
    readPaths: normalizePathDeclarations(requests.readPaths, projectRoot),
    writePaths: normalizePathDeclarations(requests.writePaths, projectRoot),
    domains: normalizeDomainDeclarations(requests.domains),
  };
}

export function projectRequestManifestHash(
  requests: NormalizedProjectAccessRequests,
  projectRoot: string,
  mode: string,
): string {
  const manifest = JSON.stringify({
    policyVersion: 2,
    projectRoot: canonicalizePath(projectRoot),
    mode,
    read: requests.readPaths.map((entry) => entry.canonicalPath).sort(),
    write: requests.writePaths.map((entry) => entry.canonicalPath).sort(),
    network: requests.domains.map((entry) => entry.domain).sort(),
  });
  return `sha256:${createHash("sha256").update(manifest).digest("hex")}`;
}

function pathRequestRoot(path: string): string {
  return path.endsWith("/**") ? path.slice(0, -3) || "/" : path;
}

function approvedPath(path: string, approvals: string[], cwd: string): boolean {
  return matchesPattern(pathRequestRoot(path), approvals, cwd);
}

function approvedDomain(domain: string, approvals: string[]): boolean {
  return approvals.some((pattern) => domainMatchesPattern(domain, pattern));
}

function domainDenied(domain: string, denied: string[]): boolean {
  return denied.some((pattern) => domainMatchesPattern(domain, pattern));
}

export function classifyProjectAccessRequests(input: {
  requests: NormalizedProjectAccessRequests;
  config: SandboxConfig;
  projectRoot: string;
  mode: string;
  modePolicy: ModePolicy;
  protectedWritePaths: string[];
  approval?: ProjectRequestApproval;
}): ProjectRequestState {
  const { requests, config, projectRoot, modePolicy, protectedWritePaths, approval } = input;
  const directReads = resolvePolicyPatterns(
    [...(config.filesystem.allowRead ?? []), ...config.filesystem.allowWrite],
    projectRoot,
  );
  const directWrites = resolvePolicyPatterns(config.filesystem.allowWrite, projectRoot);
  const approvalRead = approval?.approved.read ?? [];
  const approvalWrite = approval?.approved.write ?? [];
  const approvalNetwork = approval?.approved.network ?? [];
  const credentialDenies = (config.credentials?.files ?? [])
    .filter((entry) => entry.mode === "deny")
    .map((entry) => entry.path);
  const hardReads = [...config.filesystem.denyRead, ...credentialDenies];

  const readPaths: ClassifiedPathRequest[] = requests.readPaths.map((request) => {
    const path = pathRequestRoot(request.canonicalPath);
    const decision = evaluateReadPolicy({
      path,
      cwd: projectRoot,
      readScope: config.filesystem.readScope ?? "home",
      denyRead: hardReads,
      allowRead: directReads,
      modeBehavior: modePolicy.read,
    });
    const status: RequestStatus =
      decision === "hard-deny"
        ? "hard-denied"
        : decision === "mode-deny"
          ? "mode-denied"
          : decision === "allow" || decision === "outside-scope-allow"
            ? "already-allowed"
            : approvedPath(request.canonicalPath, [...approvalRead, ...approvalWrite], projectRoot)
              ? "previously-approved"
              : "pending";
    return { ...request, status };
  });

  const writePaths: ClassifiedPathRequest[] = requests.writePaths.map((request) => {
    const path = pathRequestRoot(request.canonicalPath);
    const hardDenied = matchesPattern(
      path,
      [...hardReads, ...config.filesystem.denyWrite, ...protectedWritePaths],
      projectRoot,
    );
    const status: RequestStatus = hardDenied
      ? "hard-denied"
      : modePolicy.write === "deny"
        ? "mode-denied"
        : matchesPattern(path, directWrites, projectRoot)
          ? "already-allowed"
          : approvedPath(request.canonicalPath, approvalWrite, projectRoot)
            ? "previously-approved"
            : "pending";
    return { ...request, status };
  });

  const directDomains = config.network?.allowedDomains ?? [];
  const deniedDomains = config.network?.deniedDomains ?? [];
  const domains: ClassifiedDomainRequest[] = requests.domains.map((request) => {
    const status: RequestStatus = domainDenied(request.domain, deniedDomains)
      ? "hard-denied"
      : modePolicy.network === "deny"
        ? "mode-denied"
        : approvedDomain(request.domain, directDomains)
          ? "already-allowed"
          : approvedDomain(request.domain, approvalNetwork)
            ? "previously-approved"
            : "pending";
    return { ...request, status };
  });

  return {
    requests,
    readPaths,
    writePaths,
    domains,
    manifestHash: projectRequestManifestHash(requests, input.projectRoot, input.mode),
    approval,
  };
}

export function pendingProjectRequestCount(state: ProjectRequestState): number {
  return [...state.readPaths, ...state.writePaths, ...state.domains].filter(
    (entry) => entry.status === "pending",
  ).length;
}

export function declaredProjectAllowances(state: ProjectRequestState): DeclaredProjectAllowances {
  return {
    readPaths: state.readPaths
      .filter((entry) => entry.status === "previously-approved")
      .map((entry) => entry.canonicalPath),
    writePaths: state.writePaths
      .filter((entry) => entry.status === "previously-approved")
      .map((entry) => entry.canonicalPath),
    domains: state.domains
      .filter((entry) => entry.status === "previously-approved")
      .map((entry) => entry.domain),
  };
}

export interface ProjectRequestSelection {
  read: string[];
  write: string[];
  network: string[];
}

export function approvedSelectionFromState(
  state: ProjectRequestState,
  newlyApproved: ProjectRequestSelection,
): ProjectRequestSelection {
  const selected = {
    read: new Set(newlyApproved.read),
    write: new Set(newlyApproved.write),
    network: new Set(newlyApproved.network),
  };
  for (const entry of state.readPaths) {
    if (entry.status === "previously-approved") selected.read.add(entry.canonicalPath);
  }
  for (const entry of state.writePaths) {
    if (entry.status === "previously-approved") selected.write.add(entry.canonicalPath);
  }
  for (const entry of state.domains) {
    if (entry.status === "previously-approved") selected.network.add(entry.domain);
  }
  return {
    read: [...selected.read].sort(),
    write: [...selected.write].sort(),
    network: [...selected.network].sort(),
  };
}
