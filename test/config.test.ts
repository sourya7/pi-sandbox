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
  addWritePathToConfig,
  applyGlobalModeProfile,
  deepMerge,
  DEFAULT_CONFIG,
  getConfigPaths,
  listGlobalSandboxModes,
  loadPolicy,
  readProjectRequestApproval,
  validateConfig,
  writeProjectRequestApproval,
} from "../src/config.ts";

function withIsolatedV2AgentDir<T>(run: () => T): T {
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-test-agent-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  writeFileSync(join(agentDir, "sandbox.json"), JSON.stringify({ policyVersion: 2 }));
  try {
    return run();
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  }
}

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
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-config-agent-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  mkdirSync(join(cwd, ".pi"));
  try {
    writeFileSync(join(agentDir, "sandbox.json"), JSON.stringify({ policyVersion: 2 }));
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
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  }
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
  const loaded = withIsolatedV2AgentDir(() => loadPolicy(cwd, "default", false));
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
  const loaded = withIsolatedV2AgentDir(() => loadPolicy(cwd, "default", true));
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
  assert.throws(
    () => withIsolatedV2AgentDir(() => loadPolicy(cwd, "default", true)),
    /cannot contain/,
  );
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

test("grant writers preserve the nested v3 schema for global profiles", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-v3-policy-write-"));
  const configPath = join(cwd, "sandbox.audit.json");
  writeFileSync(
    configPath,
    JSON.stringify({
      policyVersion: 3,
      network: { allow: [], deny: [], otherwise: "deny" },
      filesystem: {
        read: { allow: [], deny: [], otherwise: "prompt" },
        write: { allow: [], deny: [], otherwise: "deny" },
      },
    }),
  );

  addReadPathToConfig(configPath, "/read");
  addWritePathToConfig(configPath, "/write");
  const written = JSON.parse(readFileSync(configPath, "utf-8"));
  assert.deepEqual(written.filesystem.read.allow, ["/read"]);
  assert.deepEqual(written.filesystem.write.allow, ["/write"]);
  assert.equal(written.filesystem.allowRead, undefined);
  assert.equal(written.mode, undefined);
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
  assert.throws(
    () => validateConfig({ policyVersion: 1 }, "test policy"),
    /policyVersion must be 2 or 3/,
  );
});

test("v3 normalizes nested allow, deny, and otherwise policies", () => {
  const parsed = validateConfig(
    {
      policyVersion: 3,
      network: { allow: ["github.com"], deny: ["blocked.example"], otherwise: "deny" },
      filesystem: {
        read: { scope: "strict", allow: ["/docs"], deny: ["/secret"], otherwise: "prompt" },
        write: { allow: ["/tmp"], deny: ["/locked"], otherwise: "deny" },
      },
    },
    "test v3 policy",
  );

  assert.deepEqual(parsed.otherwise, { read: "prompt", write: "deny", network: "deny" });
  assert.deepEqual(parsed.network?.allowedDomains, ["github.com"]);
  assert.deepEqual(parsed.network?.deniedDomains, ["blocked.example"]);
  assert.equal(parsed.filesystem?.readScope, "strict");
  assert.deepEqual(parsed.filesystem?.allowRead, ["/docs"]);
  assert.deepEqual(parsed.filesystem?.denyRead, ["/secret"]);
  assert.deepEqual(parsed.filesystem?.allowWrite, ["/tmp"]);
  assert.deepEqual(parsed.filesystem?.denyWrite, ["/locked"]);
});

test("v3 rejects the obsolete inner mode block and v2 field names", () => {
  assert.throws(
    () =>
      validateConfig(
        {
          policyVersion: 3,
          mode: { read: "prompt", write: "prompt", network: "prompt" },
        },
        "test v3 policy",
      ),
    /inner mode block.*no longer supported/i,
  );
  assert.throws(
    () =>
      validateConfig(
        { policyVersion: 3, network: { allowedDomains: ["github.com"] } },
        "test v3 policy",
      ),
    /network\.allowedDomains.*use network\.allow/i,
  );
});

test("v3 global base requires explicit otherwise actions", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-v3-incomplete-project-"));
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-v3-incomplete-agent-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  try {
    writeFileSync(
      join(agentDir, "sandbox.json"),
      JSON.stringify({
        policyVersion: 3,
        network: { allow: [], deny: [], otherwise: "deny" },
        filesystem: {
          read: { scope: "strict", allow: [], deny: [], otherwise: "prompt" },
          write: { allow: [], deny: [] },
        },
      }),
    );
    assert.throws(
      () => loadPolicy(cwd, "default", false),
      /policyVersion 3 requires explicit filesystem\.write\.otherwise/,
    );
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  }
});

test("global mode discovery returns arbitrary safe profile names", () => {
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-mode-discovery-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  try {
    for (const name of [
      "sandbox.audit.json",
      "sandbox.read-only.json",
      "sandbox.UPPER.json",
      "sandbox.bad.name.json",
      "settings.json",
    ]) {
      writeFileSync(join(agentDir, name), "{}");
    }
    assert.deepEqual(listGlobalSandboxModes(), ["default", "audit", "read-only"]);
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  }
});

test("v3 global mode profiles replace present allows, inherit omitted allows, and union denies", () => {
  const base = {
    ...DEFAULT_CONFIG,
    network: {
      ...DEFAULT_CONFIG.network,
      allowedDomains: ["base.example"],
      deniedDomains: ["base-blocked.example"],
    },
    filesystem: {
      ...DEFAULT_CONFIG.filesystem,
      allowRead: [".", "/base-read"],
      allowWrite: [".", "/tmp"],
      denyRead: ["/base-secret"],
      denyWrite: ["/base-locked"],
    },
  };
  const merged = applyGlobalModeProfile(
    base,
    validateConfig({
      policyVersion: 3,
      network: { allow: [], deny: ["mode-blocked.example"], otherwise: "deny" },
      filesystem: {
        read: { allow: [], deny: ["/mode-secret"], otherwise: "prompt" },
        write: { allow: ["/tmp"], deny: [], otherwise: "deny" },
      },
    }),
  );

  assert.deepEqual(merged.network?.allowedDomains, []);
  assert.deepEqual(merged.network?.deniedDomains, ["base-blocked.example", "mode-blocked.example"]);
  assert.deepEqual(merged.filesystem.allowRead, []);
  assert.deepEqual(merged.filesystem.allowWrite, ["/tmp"]);
  assert.deepEqual(merged.filesystem.denyRead, ["/base-secret", "/mode-secret"]);
  assert.deepEqual(merged.filesystem.denyWrite, ["/base-locked"]);

  const inherited = applyGlobalModeProfile(
    base,
    validateConfig({
      policyVersion: 3,
      filesystem: { write: { allow: ["/mode-write"], deny: [] } },
    }),
  );
  assert.deepEqual(inherited.filesystem.allowRead, [".", "/base-read"]);
  assert.deepEqual(inherited.network?.allowedDomains, ["base.example"]);
});

test("v3 loads arbitrary named global modes with behavior and source provenance", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-v3-project-"));
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-v3-agent-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  try {
    writeFileSync(
      join(agentDir, "sandbox.json"),
      JSON.stringify({
        policyVersion: 3,
        network: {
          allow: ["base.example"],
          deny: ["base-blocked.example"],
          otherwise: "prompt",
        },
        filesystem: {
          read: {
            scope: "home",
            allow: [".", "/base-read"],
            deny: ["/base-secret"],
            otherwise: "prompt",
          },
          write: {
            allow: [".", "/tmp"],
            deny: ["/base-locked"],
            otherwise: "prompt",
          },
        },
      }),
    );
    const modePath = join(agentDir, "sandbox.audit.json");
    writeFileSync(
      modePath,
      JSON.stringify({
        policyVersion: 3,
        network: { allow: ["audit.example"], deny: ["mode-blocked.example"], otherwise: "deny" },
        filesystem: {
          read: { allow: [], deny: ["/mode-secret"] },
          write: { allow: ["/tmp"], deny: [], otherwise: "deny" },
        },
      }),
    );

    const loaded = loadPolicy(cwd, "audit", false);
    assert.equal(loaded.policyVersion, 3);
    assert.equal(loaded.modeName, "audit");
    assert.deepEqual(loaded.otherwisePolicy, {
      read: "prompt",
      write: "deny",
      network: "deny",
    });
    assert.deepEqual(loaded.otherwisePolicySources, {
      read: join(agentDir, "sandbox.json"),
      write: modePath,
      network: modePath,
    });
    assert.deepEqual(loaded.config.filesystem.allowRead, []);
    assert.deepEqual(loaded.config.filesystem.allowWrite, ["/tmp"]);
    assert.deepEqual(loaded.config.filesystem.denyRead, [
      ...DEFAULT_CONFIG.filesystem.denyRead,
      "/base-secret",
      "/mode-secret",
    ]);
    assert.deepEqual(loaded.config.network?.allowedDomains, ["audit.example"]);
    assert.equal(loaded.loadedConfigPaths.includes(modePath), true);
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  }
});

test("custom modes fail closed when missing or still use v2 semantics", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-custom-project-"));
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-custom-agent-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  try {
    writeFileSync(
      join(agentDir, "sandbox.json"),
      JSON.stringify({
        policyVersion: 2,
        filesystem: { denyRead: [], allowRead: ["."], allowWrite: ["."], denyWrite: [] },
      }),
    );
    assert.throws(() => loadPolicy(cwd, "audit", false), /mode.*audit.*not defined/i);

    writeFileSync(
      join(agentDir, "sandbox.audit.json"),
      JSON.stringify({ policyVersion: 2, filesystem: { allowRead: [] } }),
    );
    assert.throws(() => loadPolicy(cwd, "audit", false), /custom mode.*policyVersion 3/i);
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  }
});

test("v3 profiles still apply reactive project grants additively without removing hard denies", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-v3-grant-project-"));
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-v3-grant-agent-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  try {
    writeFileSync(
      join(agentDir, "sandbox.json"),
      JSON.stringify({
        policyVersion: 3,
        network: { allow: [], deny: ["blocked.example"], otherwise: "prompt" },
        filesystem: {
          read: { scope: "strict", allow: [], deny: ["/secret"], otherwise: "prompt" },
          write: { allow: [], deny: ["/locked"], otherwise: "prompt" },
        },
      }),
    );
    const grantPath = getConfigPaths(cwd).projectGrantPath;
    mkdirSync(dirname(grantPath), { recursive: true });
    writeFileSync(
      grantPath,
      JSON.stringify({
        policyVersion: 2,
        network: { allowedDomains: ["granted.example"] },
        filesystem: { allowRead: ["/granted-read"], allowWrite: ["/granted-write"] },
      }),
    );

    const loaded = loadPolicy(cwd, "default", false);
    assert.deepEqual(loaded.directConfig.filesystem.allowRead, []);
    assert.deepEqual(loaded.config.filesystem.allowRead, ["/granted-read"]);
    assert.deepEqual(loaded.config.filesystem.allowWrite, ["/granted-write"]);
    assert.equal(loaded.config.filesystem.denyRead.includes("/secret"), true);
    assert.equal(loaded.config.filesystem.denyWrite.includes("/locked"), true);
    assert.equal(loaded.config.network?.allowedDomains?.includes("granted.example"), true);
    assert.equal(loaded.config.network?.deniedDomains?.includes("blocked.example"), true);
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  }
});

test("project policy cannot define execution behavior", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-project-mode-authority-"));
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-agent-mode-authority-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  mkdirSync(join(cwd, ".pi"));
  try {
    writeFileSync(
      join(agentDir, "sandbox.json"),
      JSON.stringify({
        policyVersion: 3,
        network: { allow: [], deny: [], otherwise: "deny" },
        filesystem: {
          read: { scope: "strict", allow: ["."], deny: [], otherwise: "prompt" },
          write: { allow: [], deny: [], otherwise: "deny" },
        },
      }),
    );
    writeFileSync(
      join(cwd, ".pi", "sandbox.json"),
      JSON.stringify({
        policyVersion: 3,
        filesystem: {
          read: { allow: ["/requested-read"], otherwise: "deny" },
          write: {
            allow: ["/requested-write"],
            deny: ["project.lock"],
            otherwise: "prompt",
          },
        },
        network: { allow: ["requested.example"], otherwise: "prompt" },
      }),
    );

    const loaded = loadPolicy(cwd, "default", true);
    assert.deepEqual(loaded.otherwisePolicy, { read: "prompt", write: "deny", network: "deny" });
    assert.match(
      loaded.warnings.join("\n"),
      /Ignored unsupported project controls: filesystem\.read\.otherwise, filesystem\.write\.otherwise, network\.otherwise/,
    );
    assert.equal(loaded.config.filesystem.denyWrite.includes("project.lock"), true);
    assert.deepEqual(
      loaded.projectRequests.readPaths.map((request) => request.canonicalPath),
      ["/requested-read"],
    );
    assert.deepEqual(
      loaded.projectRequests.writePaths.map((request) => request.canonicalPath),
      ["/requested-write"],
    );
    assert.deepEqual(
      loaded.projectRequests.domains.map((request) => request.domain),
      ["requested.example"],
    );
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
  }
});
