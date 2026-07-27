import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import assert from "node:assert/strict";

import { wrapCommandWithSandboxMacOS } from "../sandbox-runtime/dist/sandbox/macos-sandbox-utils.js";
import { SandboxRuntimeConfigSchema } from "../sandbox-runtime/dist/sandbox/sandbox-config.js";
import { DEFAULT_CONFIG } from "../src/config.ts";
import { buildRuntimeConfig } from "../src/sandbox-runtime.ts";

const execFileAsync = promisify(execFile);

test("local runtime schema accepts denyReadAlways", () => {
  const parsed = SandboxRuntimeConfigSchema.safeParse({
    network: { allowedDomains: [], deniedDomains: [] },
    filesystem: {
      denyRead: ["/protected"],
      allowRead: ["/protected/project"],
      denyReadAlways: ["/protected/project/secret"],
      allowWrite: [],
      denyWrite: [],
    },
  });
  assert.equal(parsed.success, true);
});

test("macOS profile emits final deny after read, write, and pty allows", () => {
  const wrapped = wrapCommandWithSandboxMacOS({
    command: "true",
    needsNetworkRestriction: false,
    readConfig: {
      denyOnly: ["/Users"],
      allowWithinDeny: ["/Users/me/project"],
      denyAlways: ["/Users/me/project/secret"],
    },
    writeConfig: { allowOnly: ["/Users/me/project"], denyWithinAllow: [] },
    maskedFileBinds: [{ realPath: "/Users/me/project/masked-token", fakePath: "/tmp/fake-token" }],
    allowPty: true,
    binShell: "bash",
  });
  const finalIndex = wrapped.indexOf("; File read final deny");
  assert.ok(finalIndex > wrapped.indexOf("; File write"));
  assert.ok(finalIndex > wrapped.indexOf("; Pseudo-terminal (pty) support"));
  assert.ok(wrapped.slice(finalIndex).includes("/Users/me/project/secret"));
  assert.ok(wrapped.slice(finalIndex).includes("/Users/me/project/masked-token"));
  assert.ok(wrapped.slice(finalIndex).includes("file-write-unlink"));
});

test(
  "Linux strict scope starts the configured shell with discovered bootstrap reads",
  { skip: process.platform !== "linux" },
  async () => {
    const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-strict-start-"));
    const shell = process.env.SHELL ?? "bash";
    const runtime = buildRuntimeConfig(
      {
        ...DEFAULT_CONFIG,
        network: { ...DEFAULT_CONFIG.network, allowedDomains: [], allowAllUnixSockets: true },
        filesystem: {
          ...DEFAULT_CONFIG.filesystem,
          readScope: "strict",
          allowRead: [cwd],
          allowWrite: [cwd],
        },
      },
      undefined,
      cwd,
      [],
      [shell],
    );
    await SandboxManager.initialize(runtime, undefined, false);
    try {
      const wrapped = await SandboxManager.wrapWithSandbox("printf STRICT_OK", shell);
      const { stdout } = await execFileAsync(shell, ["-c", wrapped]);
      assert.equal(stdout, "STRICT_OK");
    } finally {
      SandboxManager.cleanupAfterCommand();
      await SandboxManager.reset();
    }
  },
);

test(
  "Linux final deny survives a broad allowRead and allowWrite",
  { skip: process.platform !== "linux" },
  async () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-final-deny-"));
    const allowed = join(root, "allowed.txt");
    const secret = join(root, "secret.txt");
    const secretDir = join(root, "secret-dir");
    mkdirSync(secretDir);
    writeFileSync(allowed, "VISIBLE");
    writeFileSync(secret, "NEVER-EXPOSE");
    writeFileSync(join(secretDir, "nested.txt"), "NEVER-NESTED");
    await SandboxManager.initialize(
      {
        network: { allowedDomains: [], deniedDomains: [], allowAllUnixSockets: true },
        filesystem: {
          denyRead: [root],
          allowRead: [root],
          denyReadAlways: [secret, secretDir],
          allowWrite: [root],
          denyWrite: [],
        },
      },
      undefined,
      false,
    );
    try {
      const shell = process.env.SHELL ?? "bash";
      const wrapped = await SandboxManager.wrapWithSandbox(
        `printf 'allowed='; cat ${JSON.stringify(allowed)}; printf '\\nsecret='; cat ${JSON.stringify(secret)}; printf '\\nnested='; cat ${JSON.stringify(join(secretDir, "nested.txt"))} 2>/dev/null || true`,
        shell,
      );
      const { stdout } = await execFileAsync(shell, ["-c", wrapped]);
      assert.match(stdout, /allowed=VISIBLE/);
      assert.doesNotMatch(stdout, /NEVER-EXPOSE|NEVER-NESTED/);
    } finally {
      SandboxManager.cleanupAfterCommand();
      await SandboxManager.reset();
    }
  },
);
