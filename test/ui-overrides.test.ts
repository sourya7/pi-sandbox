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
