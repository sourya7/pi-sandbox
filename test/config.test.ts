import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import { deepMerge, DEFAULT_CONFIG, getConfigPaths, loadConfig } from "../src/config.ts";

test("deepMerge merges sections while adding configured arrays", () => {
  const merged = deepMerge(DEFAULT_CONFIG, {
    enabled: false,
    network: { allowedDomains: ["example.com"], deniedDomains: ["blocked.example"] },
    filesystem: {
      denyRead: ["/secret"],
      allowRead: ["/docs"],
      allowWrite: ["/work"],
      denyWrite: ["*.secret"],
    },
  });

  assert.equal(merged.enabled, false);
  assert.equal(merged.network?.allowedDomains?.includes("github.com"), true);
  assert.equal(merged.network?.allowedDomains?.includes("example.com"), true);
  assert.equal(merged.network?.deniedDomains?.includes("blocked.example"), true);
  assert.equal(merged.filesystem?.allowRead?.includes("."), true);
  assert.equal(merged.filesystem?.allowRead?.includes("/docs"), true);
  assert.equal(merged.filesystem?.allowWrite?.includes("/tmp"), true);
  assert.equal(merged.filesystem?.allowWrite?.includes("/work"), true);
  assert.equal(merged.filesystem?.denyWrite?.includes(".env"), true);
  assert.equal(merged.filesystem?.denyWrite?.includes("*.secret"), true);
});

test("built-in defaults do not hard-deny normal home directory projects", () => {
  assert.deepEqual(DEFAULT_CONFIG.filesystem?.denyRead, []);
});

test("a later merge adds to global configuration without erasing it", () => {
  const global = deepMerge(DEFAULT_CONFIG, {
    filesystem: {
      denyRead: [],
      allowRead: ["/global"],
      allowWrite: [],
      denyWrite: [],
    },
  });
  const project = deepMerge(global, {
    filesystem: {
      denyRead: [],
      allowRead: ["/project"],
      allowWrite: [],
      denyWrite: [],
    },
  });
  assert.equal(project.filesystem?.allowRead?.includes("."), true);
  assert.equal(project.filesystem?.allowRead?.includes("/global"), true);
  assert.equal(project.filesystem?.allowRead?.includes("/project"), true);
});

test("deepMerge deduplicates additive arrays", () => {
  const merged = deepMerge(DEFAULT_CONFIG, {
    network: { allowedDomains: ["github.com", "example.com"], deniedDomains: [] },
    filesystem: { denyRead: [], allowRead: [".", "/extra"], allowWrite: [], denyWrite: [] },
  });

  assert.equal(
    merged.network?.allowedDomains?.filter((domain) => domain === "github.com").length,
    1,
  );
  assert.equal(merged.filesystem?.allowRead?.filter((path) => path === ".").length, 1);
});

test("getConfigPaths includes mode-specific files for named modes", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-config-"));
  assert.deepEqual(getConfigPaths(cwd, "read-only"), {
    globalBasePath: getConfigPaths(cwd).globalBasePath,
    globalModePath: join(dirname(getConfigPaths(cwd).globalBasePath), "sandbox.read-only.json"),
    projectBasePath: join(cwd, ".pi", "sandbox.json"),
    projectModePath: join(cwd, ".pi", "sandbox.read-only.json"),
  });
});

test("loadConfig named mode adds project base and project mode arrays", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-config-"));
  mkdirSync(join(cwd, ".pi"));
  writeFileSync(
    join(cwd, ".pi", "sandbox.json"),
    JSON.stringify({ filesystem: { allowRead: ["/project-base"], denyWrite: ["base.key"] } }),
  );
  writeFileSync(
    join(cwd, ".pi", "sandbox.read-only.json"),
    JSON.stringify({ filesystem: { allowRead: ["/project-mode"], denyWrite: ["mode.key"] } }),
  );

  const config = loadConfig(cwd, "read-only");
  assert.equal(config.filesystem?.allowRead?.includes("."), true);
  assert.equal(config.filesystem?.allowRead?.includes("/project-base"), true);
  assert.equal(config.filesystem?.allowRead?.includes("/project-mode"), true);
  assert.equal(config.filesystem?.denyWrite?.includes("base.key"), true);
  assert.equal(config.filesystem?.denyWrite?.includes("mode.key"), true);
});
