import { chmodSync, mkdtempSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import assert from "node:assert/strict";

import { applyGlobalModeProfile, DEFAULT_CONFIG, validateConfig } from "../src/config.ts";
import {
  buildRuntimeConfig,
  extractBlockedWritePath,
  extractSandboxViolation,
  filterDenyWriteForRuntime,
  supportsNodeEnvProxy,
} from "../src/sandbox-runtime.ts";
import {
  deriveConfigWithExactOverrides,
  overrideAllowances,
  type ExactSessionOverride,
} from "../src/session-overrides.ts";

test("buildRuntimeConfig adds session allowances without mutating config", () => {
  const runtime = buildRuntimeConfig(DEFAULT_CONFIG, {
    domains: ["example.com"],
    readPaths: ["/read"],
    writePaths: ["/write"],
  });
  assert.equal(runtime.network?.allowedDomains?.includes("example.com"), true);
  assert.equal(runtime.filesystem?.allowRead?.includes("/read"), true);
  assert.equal(runtime.filesystem?.allowWrite?.includes("/write"), true);
  assert.equal(runtime.filesystem?.allowRead?.includes("/write"), true);
  assert.deepEqual(runtime.filesystem?.denyRead, [process.env.HOME]);
  assert.deepEqual(runtime.filesystem?.denyReadAlways, []);
  assert.equal(runtime.enableWeakerNetworkIsolation, false);
  assert.equal(DEFAULT_CONFIG.network?.allowedDomains?.includes("example.com"), false);
});

test("v3 replacement profile reaches runtime without inherited project grants", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-v3-runtime-profile-"));
  try {
    const secret = join(cwd, "secret");
    const base = {
      ...DEFAULT_CONFIG,
      filesystem: {
        ...DEFAULT_CONFIG.filesystem,
        denyRead: [secret],
        allowRead: [cwd],
        allowWrite: [cwd, "/tmp"],
      },
    };
    const profile = applyGlobalModeProfile(
      base,
      validateConfig({
        policyVersion: 3,
        filesystem: {
          read: { allow: [], deny: [], otherwise: "deny" },
          write: { allow: ["/tmp"], deny: [], otherwise: "deny" },
        },
      }),
    );
    const runtime = buildRuntimeConfig(profile, undefined, cwd);

    assert.equal(runtime.filesystem.allowWrite?.includes(cwd), false);
    assert.equal(runtime.filesystem.allowRead?.includes(cwd), false);
    assert.equal(runtime.filesystem.allowWrite?.includes("/tmp"), true);
    assert.equal(runtime.filesystem.allowRead?.includes("/tmp"), true);
    assert.equal(runtime.filesystem.denyReadAlways?.includes(secret), true);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("buildRuntimeConfig preserves a symlink allow path and its canonical target", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-runtime-link-"));
  const target = mkdtempSync(join(tmpdir(), "pi-sandbox-runtime-target-"));
  const link = join(cwd, "profile");
  symlinkSync(target, link);
  try {
    const runtime = buildRuntimeConfig(
      {
        ...DEFAULT_CONFIG,
        filesystem: { ...DEFAULT_CONFIG.filesystem, allowRead: [link] },
      },
      undefined,
      cwd,
    );
    assert.equal(runtime.filesystem.allowRead?.includes(link), true);
    assert.equal(runtime.filesystem.allowRead?.includes(target), true);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
    rmSync(target, { recursive: true, force: true });
  }
});

test("buildRuntimeConfig filters non-existent denyWrite leaves under unwritable parents", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-runtime-"));
  chmodSync(cwd, 0o555);
  try {
    const runtime = buildRuntimeConfig(
      { ...DEFAULT_CONFIG, filesystem: { ...DEFAULT_CONFIG.filesystem, denyWrite: [".env"] } },
      undefined,
      cwd,
    );
    assert.deepEqual(runtime.filesystem?.denyWrite, []);
  } finally {
    chmodSync(cwd, 0o755);
  }
});

test("filterDenyWriteForRuntime keeps non-existent denyWrite leaves under writable parents", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-runtime-"));
  assert.deepEqual(filterDenyWriteForRuntime([".env"], cwd), [".env"]);
});

test("filterDenyWriteForRuntime keeps glob patterns", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-runtime-"));
  assert.deepEqual(filterDenyWriteForRuntime([".env.*", "*.pem"], cwd), [".env.*", "*.pem"]);
});

test("filterDenyWriteForRuntime keeps existing denyWrite paths", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-runtime-"));
  mkdirSync(join(cwd, ".env"));
  assert.deepEqual(filterDenyWriteForRuntime([".env"], cwd), [".env"]);
});

test("extractBlockedWritePath recognizes sandbox violation annotations", () => {
  assert.equal(
    extractBlockedWritePath(
      "bash failed\n<sandbox_violations>\ndeny openat /home/mojo/test.txt\n</sandbox_violations>",
    ),
    "/home/mojo/test.txt",
  );
});

test("extractBlockedWritePath recognizes shell sandbox errors", () => {
  assert.equal(
    extractBlockedWritePath("bash: line 1: /private/file: Operation not permitted"),
    "/private/file",
  );
  assert.equal(
    extractBlockedWritePath(
      "/run/current-system/sw/bin/bash: line 4: /home/mojo/test.txt: Read-only file system",
    ),
    "/home/mojo/test.txt",
  );
  assert.equal(extractBlockedWritePath("permission denied"), null);
});

test("extractSandboxViolation classifies read, write, and network annotations", () => {
  assert.deepEqual(
    extractSandboxViolation(
      "<sandbox_violations>\ndeny(1) file-read-data /private/secret\n</sandbox_violations>",
    ),
    { type: "read", path: "/private/secret", raw: "deny(1) file-read-data /private/secret" },
  );
  assert.deepEqual(
    extractSandboxViolation(
      "<sandbox_violations>\ndeny(1) file-write-create /private/out\n</sandbox_violations>",
    ),
    { type: "write", path: "/private/out", raw: "deny(1) file-write-create /private/out" },
  );
  assert.deepEqual(
    extractSandboxViolation(
      '<sandbox_violations>\ndeny(1) network-outbound remote ip "example.com:443"\n</sandbox_violations>',
    ),
    {
      type: "network",
      host: "example.com",
      raw: 'deny(1) network-outbound remote ip "example.com:443"',
    },
  );
});

test("exact override derivation removes only the selected runtime final deny", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-runtime-override-"));
  const target = join(cwd, ".env");
  const sibling = join(cwd, ".env.local");
  const override: ExactSessionOverride = {
    operation: "read",
    configuredValue: ".env",
    canonicalPath: target,
    removedRules: [{ field: "denyRead", configuredValue: ".env" }],
    createdAt: new Date(0).toISOString(),
  };
  const derived = deriveConfigWithExactOverrides(
    {
      ...DEFAULT_CONFIG,
      filesystem: {
        ...DEFAULT_CONFIG.filesystem,
        denyRead: [".env", ".env.local"],
        allowRead: [],
      },
    },
    [override],
    cwd,
  );
  const paths = overrideAllowances([override]);
  const runtime = buildRuntimeConfig(
    derived,
    { domains: [], readPaths: paths.readPaths, writePaths: paths.writePaths },
    cwd,
  );
  assert.equal(runtime.filesystem.denyReadAlways?.includes(target), false);
  assert.equal(runtime.filesystem.denyReadAlways?.includes(sibling), true);
  assert.equal(runtime.filesystem.allowRead?.includes(target), true);
});

test("v2 runtime config maps user denyRead to authoritative final denies", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-v2-runtime-"));
  const secret = join(cwd, "secret");
  const policyFile = join(cwd, ".pi", "sandbox.json");
  const runtime = buildRuntimeConfig(
    {
      ...DEFAULT_CONFIG,
      filesystem: {
        ...DEFAULT_CONFIG.filesystem,
        readScope: "strict",
        denyRead: [secret],
        allowRead: [cwd],
        allowWrite: [cwd],
        denyWrite: [],
      },
    },
    undefined,
    cwd,
    [policyFile],
  );
  assert.deepEqual(runtime.filesystem?.denyRead, ["/"]);
  assert.equal(runtime.filesystem?.denyReadAlways?.includes(secret), true);
  assert.equal(runtime.filesystem?.denyWrite.includes(secret), true);
  assert.equal(runtime.filesystem?.denyWrite.includes(policyFile), true);
});

test("credential file deny rules use the final read-deny layer", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-credential-runtime-"));
  const credential = join(cwd, "token");
  const runtime = buildRuntimeConfig(
    {
      ...DEFAULT_CONFIG,
      credentials: { files: [{ path: credential, mode: "deny" }] },
    },
    undefined,
    cwd,
  );
  assert.equal(runtime.filesystem?.denyReadAlways?.includes(credential), true);
  assert.equal(runtime.filesystem?.denyWrite.includes(credential), true);
});

test("cursor-aware annotation excludes historical violations", () => {
  SandboxManager.updateConfig(buildRuntimeConfig(DEFAULT_CONFIG));
  const store = SandboxManager.getSandboxViolationStore();
  const command = "printf replay-test";
  const encodedCommand = Buffer.from(command.slice(0, 100)).toString("base64");

  store.clear();
  try {
    store.addViolation({
      line: "deny openat /historical",
      command,
      encodedCommand,
      timestamp: new Date(),
    });
    const cursor = store.getCursor();

    assert.match(SandboxManager.annotateStderrWithSandboxFailures(command, ""), /historical/);
    assert.equal(SandboxManager.annotateStderrWithSandboxFailures(command, "", cursor), "");

    store.addViolation({
      line: "deny openat /current",
      command,
      encodedCommand,
      timestamp: new Date(),
    });
    const annotated = SandboxManager.annotateStderrWithSandboxFailures(command, "", cursor);
    assert.doesNotMatch(annotated, /historical/);
    assert.match(annotated, /current/);
  } finally {
    store.clear();
  }
});

test("supportsNodeEnvProxy observes Node release boundaries", () => {
  assert.equal(supportsNodeEnvProxy("22.20.0"), false);
  assert.equal(supportsNodeEnvProxy("22.21.0"), true);
  assert.equal(supportsNodeEnvProxy("23.9.0"), false);
  assert.equal(supportsNodeEnvProxy("24.0.0"), true);
});
