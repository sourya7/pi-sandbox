import {
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import {
  addReadPathToConfig,
  deepMerge,
  DEFAULT_CONFIG,
  getConfigPaths,
  loadPolicy,
  readProjectRequestApproval,
  validateConfig,
  writeProjectRequestApproval,
} from "../src/config.ts";

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
  const paths = getConfigPaths(cwd, "read-only");
  assert.deepEqual(paths, {
    globalBasePath: getConfigPaths(cwd).globalBasePath,
    globalModePath: join(dirname(getConfigPaths(cwd).globalBasePath), "sandbox.read-only.json"),
    projectBasePath: join(cwd, ".pi", "sandbox.json"),
    projectModePath: join(cwd, ".pi", "sandbox.read-only.json"),
    projectGrantPath: paths.projectGrantPath,
    projectRequestApprovalPath: paths.projectRequestApprovalPath,
  });
  assert.match(
    paths.projectRequestApprovalPath,
    /sandbox-projects\/.+\.read-only\.requests\.json$/,
  );
  assert.match(paths.projectGrantPath, /sandbox-projects\/.+\.read-only\.json$/);
});

test("loadPolicy extracts project base and mode allows as requests", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-config-"));
  mkdirSync(join(cwd, ".pi"));
  writeFileSync(
    join(cwd, ".pi", "sandbox.json"),
    JSON.stringify({
      network: { allowedDomains: ["project.example"], deniedDomains: ["blocked.example"] },
      filesystem: { allowRead: ["project-base"], denyWrite: ["base.key"] },
    }),
  );
  writeFileSync(
    join(cwd, ".pi", "sandbox.read-only.json"),
    JSON.stringify({ filesystem: { allowRead: ["project-mode"], denyWrite: ["mode.key"] } }),
  );

  const loaded = loadPolicy(cwd, "read-only", true);
  assert.equal(loaded.config.policyVersion, 2);
  assert.equal(loaded.config.filesystem.readScope, "home");
  assert.equal(loaded.config.filesystem.allowRead?.includes("."), true);
  assert.equal(loaded.config.filesystem.allowRead?.includes("project-base"), false);
  assert.equal(loaded.config.filesystem.allowRead?.includes("project-mode"), false);
  assert.deepEqual(
    loaded.projectRequests.readPaths.map((request) => request.canonicalPath),
    [join(cwd, "project-base"), join(cwd, "project-mode")],
  );
  assert.equal(loaded.config.filesystem.denyWrite.includes("base.key"), true);
  assert.equal(loaded.config.filesystem.denyWrite.includes("mode.key"), true);
  assert.equal(loaded.config.network?.allowedDomains?.includes("project.example"), false);
  assert.equal(loaded.config.network?.deniedDomains?.includes("blocked.example"), true);
  assert.deepEqual(
    loaded.projectRequests.domains.map((request) => request.domain),
    ["project.example"],
  );
});

test("untrusted project policy is not loaded", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-untrusted-"));
  mkdirSync(join(cwd, ".pi"));
  writeFileSync(
    join(cwd, ".pi", "sandbox.json"),
    JSON.stringify({
      filesystem: { denyRead: ["private-marker"], allowRead: [], allowWrite: [], denyWrite: [] },
    }),
  );
  const loaded = loadPolicy(cwd, "default", false);
  assert.equal(loaded.config.filesystem.denyRead.includes("private-marker"), false);
  assert.equal(loaded.projectTrusted, false);
});

test("trusted project external allows become requests and powerful controls are ignored", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-project-trust-"));
  mkdirSync(join(cwd, ".pi"));
  writeFileSync(
    join(cwd, ".pi", "sandbox.json"),
    JSON.stringify({
      enabled: false,
      filesystem: { allowRead: ["/etc"], allowWrite: ["/var/out"], denyRead: [], denyWrite: [] },
    }),
  );
  const loaded = loadPolicy(cwd, "default", true);
  assert.notEqual(loaded.config.enabled, false);
  assert.equal(loaded.config.filesystem.allowRead?.includes("/etc"), false);
  assert.equal(loaded.config.filesystem.allowWrite.includes("/var/out"), false);
  assert.deepEqual(
    loaded.projectRequests.readPaths.map((request) => request.canonicalPath),
    ["/etc"],
  );
  assert.deepEqual(
    loaded.projectRequests.writePaths.map((request) => request.canonicalPath),
    ["/var/out"],
  );
  assert.match(loaded.warnings.join("\n"), /Ignored unsupported project controls: enabled/);
});

test("project wildcard domain request is rejected", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-project-domain-"));
  mkdirSync(join(cwd, ".pi"));
  writeFileSync(
    join(cwd, ".pi", "sandbox.json"),
    JSON.stringify({ network: { allowedDomains: ["*"] } }),
  );
  assert.throws(() => loadPolicy(cwd, "default", true), /cannot contain/);
});

test("request approvals are mode/root-bound and safely persisted", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-approval-"));
  const path = join(cwd, "approvals", "request.json");
  const requests = { readPaths: [], writePaths: [], domains: [] };
  const written = writeProjectRequestApproval(path, cwd, "build", requests, {
    read: ["/read"],
    write: ["/write"],
    network: ["example.com"],
  });
  const warnings: string[] = [];
  assert.deepEqual(readProjectRequestApproval(path, cwd, "build", warnings), written);
  assert.deepEqual(warnings, []);
  assert.equal((lstatSync(path).mode & 0o777).toString(8), "600");

  const wrongModeWarnings: string[] = [];
  assert.equal(readProjectRequestApproval(path, cwd, "default", wrongModeWarnings), undefined);
  assert.match(wrongModeWarnings.join("\n"), /mode does not match/);
});

test("request approval writer refuses symlinked approval directories", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-approval-link-"));
  const realDirectory = join(cwd, "real");
  const linkedDirectory = join(cwd, "linked");
  mkdirSync(realDirectory);
  symlinkSync(realDirectory, linkedDirectory);
  assert.throws(
    () =>
      writeProjectRequestApproval(
        join(linkedDirectory, "request.json"),
        cwd,
        "default",
        { readPaths: [], writePaths: [], domains: [] },
        { read: [], write: [], network: [] },
      ),
    /symlinked approval directory/,
  );
});

test("grant writers create version 2 policy files", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-policy-write-"));
  const configPath = join(cwd, "sandbox.json");
  addReadPathToConfig(configPath, "/allowed");
  const written = JSON.parse(readFileSync(configPath, "utf-8"));
  assert.equal(written.policyVersion, 2);
  assert.deepEqual(written.filesystem.allowRead, ["/allowed"]);
});

test("trusted grant writer refuses symlinked policy files", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-policy-write-"));
  const real = join(cwd, "real.json");
  const link = join(cwd, "sandbox.json");
  writeFileSync(real, "{}");
  symlinkSync(real, link);
  assert.throws(() => addReadPathToConfig(link, "/allowed"), /symlinked sandbox policy/);
});

test("versionless policies reject non-portable filesystem globs", () => {
  assert.throws(
    () =>
      validateConfig(
        {
          filesystem: { denyRead: ["**/.env"], allowRead: [], allowWrite: [], denyWrite: [] },
        },
        "test policy",
      ),
    /not portable/,
  );
});

test("policy version 1 is rejected", () => {
  assert.throws(() => validateConfig({ policyVersion: 1 }, "test policy"), /only policyVersion 2/);
});
