import { execFile } from "node:child_process";
import { once } from "node:events";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import assert from "node:assert/strict";

import { DEFAULT_CONFIG } from "../src/config.ts";
import { buildRuntimeConfig } from "../src/sandbox-runtime.ts";

const execFileAsync = promisify(execFile);

test("upstream runtime manager is process-global", async () => {
  const secondImport = await import("@anthropic-ai/sandbox-runtime");
  assert.equal(secondImport.SandboxManager, SandboxManager);
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
  "final deny survives a broad allowRead and allowWrite",
  { skip: !["linux", "darwin"].includes(process.platform) },
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
          denyRead: [root, secret, secretDir],
          allowRead: [root],
          allowWrite: [root],
          denyWrite: [],
        },
      },
      undefined,
      false,
    );
    try {
      const shell = process.env.SHELL ?? "bash";
      const moved = join(root, "moved-secret.txt");
      const wrapped = await SandboxManager.wrapWithSandbox(
        `printf 'allowed='; cat ${JSON.stringify(allowed)}; printf '\\nsecret='; cat ${JSON.stringify(secret)} 2>/dev/null || true; printf HACKED > ${JSON.stringify(secret)} 2>/dev/null || true; mv ${JSON.stringify(secret)} ${JSON.stringify(moved)} 2>/dev/null || true; printf '\\nnested='; cat ${JSON.stringify(join(secretDir, "nested.txt"))} 2>/dev/null || true`,
        shell,
      );
      const { stdout } = await execFileAsync(shell, ["-c", wrapped]);
      assert.match(stdout, /allowed=VISIBLE/);
      assert.doesNotMatch(stdout, /NEVER-EXPOSE|NEVER-NESTED/);
      assert.equal(readFileSync(secret, "utf8"), "NEVER-EXPOSE");
      assert.equal(existsSync(moved), false);
    } finally {
      SandboxManager.cleanupAfterCommand();
      await SandboxManager.reset();
    }
  },
);

test(
  "Linux resolved-address guard blocks an allowed hostname aimed at loopback",
  { skip: process.platform !== "linux" },
  async () => {
    let requests = 0;
    const server = createServer((_request, response) => {
      requests++;
      response.end("HOST_SERVICE_REACHED");
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const shell = process.env.SHELL ?? "bash";
    await SandboxManager.initialize(
      {
        network: {
          allowedDomains: ["localhost"],
          deniedDomains: [],
          deniedResolvedAddresses: ["10.0.0.0/8"],
          allowAllUnixSockets: true,
        },
        filesystem: { denyRead: [], allowRead: [], allowWrite: [], denyWrite: [] },
      },
      undefined,
      false,
    );
    try {
      const script = `fetch('http://localhost:${address.port}').then(async r=>console.log('STATUS',r.status,await r.text())).catch(()=>console.log('ADDRESS_BLOCKED'))`;
      const wrapped = await SandboxManager.wrapWithSandbox(
        `NODE_USE_ENV_PROXY=1 ${JSON.stringify(process.execPath)} -e ${JSON.stringify(script)}`,
        shell,
      );
      const { stdout } = await execFileAsync(shell, ["-c", wrapped]);
      assert.equal(requests, 0);
      assert.doesNotMatch(stdout, /HOST_SERVICE_REACHED/);
      assert.match(stdout, /ADDRESS_BLOCKED|STATUS 403/);
    } finally {
      SandboxManager.cleanupAfterCommand();
      await SandboxManager.reset();
      server.closeAllConnections();
      server.close();
    }
  },
);

test(
  "Linux packaged seccomp helper blocks Unix socket creation",
  { skip: process.platform !== "linux" },
  async () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-seccomp-"));
    const socketPath = join(root, "server.sock");
    const shell = process.env.SHELL ?? "bash";
    await SandboxManager.initialize(
      {
        network: { allowedDomains: [], deniedDomains: [], allowAllUnixSockets: false },
        filesystem: {
          denyRead: [],
          allowRead: [],
          allowWrite: [root],
          denyWrite: [],
        },
      },
      undefined,
      false,
    );
    try {
      const script = `const n=require('node:net');const s=n.createServer();s.on('error',()=>{console.log('SOCKET_BLOCKED')});s.listen(${JSON.stringify(socketPath)},()=>{console.log('SOCKET_OPEN');s.close()})`;
      const wrapped = await SandboxManager.wrapWithSandbox(
        `${JSON.stringify(process.execPath)} -e ${JSON.stringify(script)}`,
        shell,
      );
      const { stdout } = await execFileAsync(shell, ["-c", wrapped]);
      assert.match(stdout, /SOCKET_BLOCKED/);
      assert.doesNotMatch(stdout, /SOCKET_OPEN/);
      assert.equal(existsSync(socketPath), false);
    } finally {
      SandboxManager.cleanupAfterCommand();
      await SandboxManager.reset();
      rmSync(root, { recursive: true, force: true });
    }
  },
);

test(
  "Linux accepts and enforces a non-existent denyWrite leaf",
  { skip: process.platform !== "linux" },
  async () => {
    const root = mkdtempSync(join(tmpdir(), "pi-sandbox-missing-deny-"));
    const denied = join(root, "future.txt");
    const shell = process.env.SHELL ?? "bash";
    await SandboxManager.initialize(
      {
        network: { allowedDomains: [], deniedDomains: [], allowAllUnixSockets: true },
        filesystem: {
          denyRead: [],
          allowRead: [],
          allowWrite: [root],
          denyWrite: [denied],
        },
      },
      undefined,
      false,
    );
    try {
      const wrapped = await SandboxManager.wrapWithSandbox(
        `printf BLOCKED > ${JSON.stringify(denied)} 2>/dev/null || true`,
        shell,
      );
      await execFileAsync(shell, ["-c", wrapped]);
      // The runtime creates an empty host mount-point stub for an absent deny.
      assert.equal(readFileSync(denied, "utf8"), "");
      SandboxManager.cleanupAfterCommand();
      assert.equal(existsSync(denied), false);
    } finally {
      SandboxManager.cleanupAfterCommand();
      await SandboxManager.reset();
      rmSync(root, { recursive: true, force: true });
    }
  },
);

test(
  "Linux strict scope follows an explicitly allowed multi-link symlink chain",
  { skip: process.platform !== "linux" },
  async () => {
    const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-link-root-"));
    const middleRoot = mkdtempSync(join(tmpdir(), "pi-sandbox-link-middle-"));
    const targetRoot = mkdtempSync(join(tmpdir(), "pi-sandbox-link-target-"));
    const target = join(targetRoot, "visible.txt");
    const middle = join(middleRoot, "middle");
    const link = join(cwd, "entry");
    writeFileSync(target, "CHAIN_OK");
    symlinkSync(target, middle);
    symlinkSync(middle, link);
    const shell = process.env.SHELL ?? "bash";
    const runtime = buildRuntimeConfig(
      {
        ...DEFAULT_CONFIG,
        network: { ...DEFAULT_CONFIG.network, allowedDomains: [], allowAllUnixSockets: true },
        filesystem: {
          ...DEFAULT_CONFIG.filesystem,
          readScope: "strict",
          allowRead: [link, middle],
          allowWrite: [],
        },
      },
      undefined,
      cwd,
      [],
      [shell],
    );
    await SandboxManager.initialize(runtime, undefined, false);
    try {
      const wrapped = await SandboxManager.wrapWithSandbox(`cat ${JSON.stringify(link)}`, shell);
      const { stdout } = await execFileAsync(shell, ["-c", wrapped]);
      assert.equal(stdout, "CHAIN_OK");
    } finally {
      SandboxManager.cleanupAfterCommand();
      await SandboxManager.reset();
      rmSync(cwd, { recursive: true, force: true });
      rmSync(middleRoot, { recursive: true, force: true });
      rmSync(targetRoot, { recursive: true, force: true });
    }
  },
);
