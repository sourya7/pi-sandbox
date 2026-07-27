import { chmodSync, mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import { DEFAULT_CONFIG } from "../src/config.ts";
import {
  buildRuntimeConfig,
  extractBlockedWritePath,
  extractSandboxViolation,
  filterDenyWriteForRuntime,
  supportsNodeEnvProxy,
} from "../src/sandbox-runtime.ts";

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

test("supportsNodeEnvProxy observes Node release boundaries", () => {
  assert.equal(supportsNodeEnvProxy("22.20.0"), false);
  assert.equal(supportsNodeEnvProxy("22.21.0"), true);
  assert.equal(supportsNodeEnvProxy("23.9.0"), false);
  assert.equal(supportsNodeEnvProxy("24.0.0"), true);
});
