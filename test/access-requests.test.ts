import { mkdtempSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import {
  approvedSelectionFromState,
  classifyProjectAccessRequests,
  declaredProjectAllowances,
  normalizeProjectAccessRequests,
  pendingProjectRequestCount,
  projectRequestManifestHash,
  type ProjectAccessRequests,
  type ProjectRequestApproval,
} from "../src/access-requests.ts";
import { DEFAULT_CONFIG, type SandboxConfig } from "../src/config.ts";
import { getModePolicy } from "../src/modes.ts";

function declaration(value: string, sourcePath = ".pi/sandbox.json") {
  return { value, sourcePath, sourceKind: "project-base" as const };
}

function requests(values: {
  read?: string[];
  write?: string[];
  network?: string[];
}): ProjectAccessRequests {
  return {
    readPaths: (values.read ?? []).map((value) => declaration(value)),
    writePaths: (values.write ?? []).map((value) => declaration(value)),
    domains: (values.network ?? []).map((value) => declaration(value)),
  };
}

function strictConfig(overrides: Partial<SandboxConfig["filesystem"]> = {}): SandboxConfig {
  return {
    ...structuredClone(DEFAULT_CONFIG),
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: {
      ...structuredClone(DEFAULT_CONFIG.filesystem),
      readScope: "strict",
      allowRead: ["."],
      allowWrite: ["."],
      denyWrite: [],
      ...overrides,
    },
  };
}

function classify(
  projectRoot: string,
  raw: ProjectAccessRequests,
  options: {
    config?: SandboxConfig;
    mode?: string;
    approval?: ProjectRequestApproval;
    protectedWritePaths?: string[];
  } = {},
) {
  const mode = options.mode ?? "default";
  return classifyProjectAccessRequests({
    requests: normalizeProjectAccessRequests(raw, projectRoot),
    config: options.config ?? strictConfig(),
    projectRoot,
    mode,
    modePolicy: getModePolicy(mode),
    protectedWritePaths: options.protectedWritePaths ?? [],
    approval: options.approval,
  });
}

test("normalization resolves relatives, symlinks, nonexistent tails, and duplicate provenance", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-request-root-"));
  const target = mkdtempSync(join(tmpdir(), "pi-request-target-"));
  const link = join(root, "shared");
  symlinkSync(target, link);
  mkdirSync(join(root, "existing"));
  const raw = requests({ read: ["shared", "existing/missing/file"] });
  raw.readPaths.push({
    value: "shared",
    sourcePath: ".pi/sandbox.build.json",
    sourceKind: "project-mode",
  });

  const normalized = normalizeProjectAccessRequests(raw, root);
  assert.equal(normalized.readPaths[0].canonicalPath, join(root, "existing", "missing", "file"));
  assert.equal(normalized.readPaths[1].canonicalPath, target);
  assert.equal(normalized.readPaths[1].sources.length, 2);
});

test("manifest hash is stable across declaration order", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-request-hash-"));
  const one = normalizeProjectAccessRequests(requests({ read: ["b", "a"] }), root);
  const two = normalizeProjectAccessRequests(requests({ read: ["a", "b"] }), root);
  assert.equal(
    projectRequestManifestHash(one, root, "default"),
    projectRequestManifestHash(two, root, "default"),
  );
});

test("classification distinguishes already allowed, pending, and scope-allowed reads", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-request-classify-"));
  const external = mkdtempSync(join(tmpdir(), "pi-request-external-"));
  const state = classify(root, requests({ read: [".", external], write: [".", external] }));
  assert.deepEqual(
    state.readPaths.map((entry) => entry.status),
    ["already-allowed", "pending"],
  );
  assert.deepEqual(
    state.writePaths.map((entry) => entry.status),
    ["already-allowed", "pending"],
  );
  assert.equal(pendingProjectRequestCount(state), 2);

  const openState = classify(root, requests({ read: [external] }), {
    config: strictConfig({ readScope: "open" }),
  });
  assert.equal(openState.readPaths[0].status, "already-allowed");
});

test("hard denies and read-only mode outrank approvals", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-request-deny-"));
  const secret = join(root, "secret");
  const output = join(root, "output");
  const normalized = normalizeProjectAccessRequests(
    requests({ read: [secret], write: [secret, output], network: ["blocked.example"] }),
    root,
  );
  const approval: ProjectRequestApproval = {
    policyVersion: 2,
    projectRoot: root,
    mode: "read-only",
    manifestHash: projectRequestManifestHash(normalized, root, "read-only"),
    approvedAt: new Date(0).toISOString(),
    approved: {
      read: [secret],
      write: [secret, output],
      network: ["blocked.example"],
    },
  };
  const config = strictConfig({ denyRead: [secret] });
  config.network = { allowedDomains: [], deniedDomains: ["*.example"] };
  const state = classifyProjectAccessRequests({
    requests: normalized,
    config,
    projectRoot: root,
    mode: "read-only",
    modePolicy: getModePolicy("read-only"),
    protectedWritePaths: [],
    approval,
  });
  assert.equal(state.readPaths[0].status, "hard-denied");
  assert.deepEqual(
    state.writePaths.map((entry) => entry.status),
    ["mode-denied", "hard-denied"],
  );
  assert.equal(state.domains[0].status, "hard-denied");
});

test("unchanged and narrower requests reuse approval without broadening active access", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-request-approved-"));
  const broad = mkdtempSync(join(tmpdir(), "pi-request-approved-external-"));
  const normalized = normalizeProjectAccessRequests(
    requests({ read: [join(broad, "child")] }),
    root,
  );
  const approval: ProjectRequestApproval = {
    policyVersion: 2,
    projectRoot: root,
    mode: "default",
    manifestHash: "sha256:old",
    approvedAt: new Date(0).toISOString(),
    approved: { read: [broad], write: [], network: [] },
  };
  const state = classifyProjectAccessRequests({
    requests: normalized,
    config: strictConfig(),
    projectRoot: root,
    mode: "default",
    modePolicy: getModePolicy("default"),
    protectedWritePaths: [],
    approval,
  });
  assert.equal(state.readPaths[0].status, "previously-approved");
  assert.deepEqual(declaredProjectAllowances(state).readPaths, [join(broad, "child")]);
});

test("approval reconciliation drops removed capabilities and leaves expansions pending", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-request-reconcile-"));
  const oldPath = mkdtempSync(join(tmpdir(), "pi-request-old-"));
  const expandedPath = join(oldPath, "..");
  const normalized = normalizeProjectAccessRequests(requests({ read: [expandedPath] }), root);
  const approval: ProjectRequestApproval = {
    policyVersion: 2,
    projectRoot: root,
    mode: "default",
    manifestHash: "sha256:old",
    approvedAt: new Date(0).toISOString(),
    approved: { read: [oldPath, "/removed"], write: [], network: [] },
  };
  const state = classifyProjectAccessRequests({
    requests: normalized,
    config: strictConfig(),
    projectRoot: root,
    mode: "default",
    modePolicy: getModePolicy("default"),
    protectedWritePaths: [],
    approval,
  });
  assert.equal(state.readPaths[0].status, "pending");
  assert.deepEqual(approvedSelectionFromState(state, { read: [], write: [], network: [] }), {
    read: [],
    write: [],
    network: [],
  });
});

test("approved write implies read approval while protected paths remain denied", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-request-write-"));
  const external = mkdtempSync(join(tmpdir(), "pi-request-write-external-"));
  const normalized = normalizeProjectAccessRequests(
    requests({ read: [external], write: [external] }),
    root,
  );
  const approval: ProjectRequestApproval = {
    policyVersion: 2,
    projectRoot: root,
    mode: "default",
    manifestHash: projectRequestManifestHash(normalized, root, "default"),
    approvedAt: new Date(0).toISOString(),
    approved: { read: [], write: [external], network: [] },
  };
  const state = classifyProjectAccessRequests({
    requests: normalized,
    config: strictConfig(),
    projectRoot: root,
    mode: "default",
    modePolicy: getModePolicy("default"),
    protectedWritePaths: [external],
    approval,
  });
  assert.equal(state.readPaths[0].status, "previously-approved");
  assert.equal(state.writePaths[0].status, "hard-denied");
});
