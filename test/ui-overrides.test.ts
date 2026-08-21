import test from "node:test";

import assert from "node:assert/strict";

import { DEFAULT_CONFIG, type LoadedSandboxPolicy } from "../src/config.ts";
import { type ExactSessionOverride } from "../src/session-overrides.ts";
import { formatSandboxConfiguration, formatSandboxStatus } from "../src/ui.ts";

const override: ExactSessionOverride = {
  operation: "read",
  configuredValue: ".env",
  canonicalPath: "/project/.env",
  removedRules: [{ field: "denyRead", configuredValue: ".env" }],
  createdAt: new Date(0).toISOString(),
};

test("status warns when exact deny overrides are active", () => {
  assert.match(
    formatSandboxStatus(DEFAULT_CONFIG, "default", "active", 1),
    /1 exact deny override/,
  );
  assert.doesNotMatch(formatSandboxStatus(DEFAULT_CONFIG), /exact deny override/);
});

test("configuration distinguishes configured and effective denies", () => {
  const configured = {
    ...DEFAULT_CONFIG,
    filesystem: { ...DEFAULT_CONFIG.filesystem, denyRead: [".env"] },
  };
  const effective = {
    ...configured,
    filesystem: { ...configured.filesystem, denyRead: [] },
  };
  const loaded: LoadedSandboxPolicy = {
    policyVersion: 2,
    modeName: "default",
    otherwisePolicy: { read: "prompt", write: "prompt", network: "prompt" },
    otherwisePolicySources: {
      read: "<built-in:v2-default>",
      write: "<built-in:v2-default>",
      network: "<built-in:v2-default>",
    },
    legacyCategoricalDenies: { read: false, write: false, network: false },
    loadedConfigPaths: [],
    configFileStates: {
      globalBase: "not-found",
      globalMode: "not-applicable",
      projectBase: "not-found",
      projectMode: "not-applicable",
      projectGrant: "not-found",
      projectRequestApproval: "not-found",
    },
    config: configured,
    directConfig: configured,
    paths: {
      globalBasePath: "/global.json",
      projectBasePath: "/project/.pi/sandbox.json",
      projectGrantPath: "/grant.json",
      projectRequestApprovalPath: "/requests.json",
    },
    projectRoot: "/project",
    projectTrusted: true,
    projectRequests: { readPaths: [], writePaths: [], domains: [] },
    warnings: [],
    protectedWritePaths: ["/project/.pi/sandbox.json"],
  };
  const output = formatSandboxConfiguration(
    loaded,
    { domains: [], readPaths: [], writePaths: [] },
    "default",
    "active",
    [],
    undefined,
    effective,
    [override],
  );
  assert.match(output, /Configured hard deny read: \.env/);
  assert.match(output, /Effective hard deny read:  \(none\)/);
  assert.match(output, /read: \/project\/\.env/);
  assert.match(output, /removed: denyRead \.env/);
});

test("configuration reports data-driven mode provenance and config load states", () => {
  const loaded: LoadedSandboxPolicy = {
    policyVersion: 3,
    modeName: "audit",
    otherwisePolicy: { read: "prompt", write: "deny", network: "deny" },
    otherwisePolicySources: {
      read: "/agent/sandbox.audit.json",
      write: "/agent/sandbox.audit.json",
      network: "/agent/sandbox.audit.json",
    },
    legacyCategoricalDenies: { read: false, write: false, network: false },
    loadedConfigPaths: ["/agent/sandbox.json", "/agent/sandbox.audit.json"],
    configFileStates: {
      globalBase: "loaded",
      globalMode: "loaded",
      projectBase: "not-found",
      projectMode: "not-found",
      projectGrant: "not-found",
      projectRequestApproval: "not-found",
    },
    config: DEFAULT_CONFIG,
    directConfig: DEFAULT_CONFIG,
    paths: {
      globalBasePath: "/agent/sandbox.json",
      globalModePath: "/agent/sandbox.audit.json",
      projectBasePath: "/project/.pi/sandbox.json",
      projectModePath: "/project/.pi/sandbox.audit.json",
      projectGrantPath: "/agent/sandbox-projects/audit.json",
      projectRequestApprovalPath: "/agent/sandbox-projects/audit.requests.json",
    },
    projectRoot: "/project",
    projectTrusted: true,
    projectRequests: { readPaths: [], writePaths: [], domains: [] },
    warnings: [],
    protectedWritePaths: [],
  };

  const output = formatSandboxConfiguration(loaded, {
    domains: [],
    readPaths: [],
    writePaths: [],
  });
  assert.match(output, /Policy version: 3/);
  assert.match(output, /Active mode: audit/);
  assert.match(output, /Otherwise sources:[\s\S]*\/agent\/sandbox\.audit\.json/);
  assert.match(output, /Write:\s+deny/);
  assert.match(output, /Network:\s+deny/);
  assert.match(output, /Global base:\s+\/agent\/sandbox\.json \(loaded\)/);
  assert.match(output, /Project base:\s+\/project\/\.pi\/sandbox\.json \(not found\)/);
  assert.match(output, /Effective allowed: .*github\.com/);
  assert.match(output, /Effective allow write: \., \/tmp/);
});
