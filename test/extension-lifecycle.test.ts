import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import assert from "node:assert/strict";

import { getConfigPaths } from "../src/config.ts";
import sandboxExtension from "../src/extension.ts";

interface ExtensionHarness {
  handlers: Map<string, Array<(event: any, ctx: any) => Promise<unknown>>>;
  commands: Map<string, { handler: (args: unknown, ctx: any) => Promise<void> }>;
  pi: any;
}

function createExtensionHarness(): ExtensionHarness {
  const handlers = new Map<string, Array<(event: any, ctx: any) => Promise<unknown>>>();
  const commands = new Map<string, { handler: (args: unknown, ctx: any) => Promise<void> }>();
  const flags = new Map<string, unknown>();
  const pi = {
    registerFlag(name: string, options: { default?: unknown }) {
      flags.set(name, options.default);
    },
    getFlag(name: string) {
      return flags.get(name);
    },
    on(name: string, handler: (event: any, ctx: any) => Promise<unknown>) {
      const registered = handlers.get(name) ?? [];
      registered.push(handler);
      handlers.set(name, registered);
    },
    registerTool() {},
    registerCommand(
      name: string,
      command: { handler: (args: unknown, ctx: any) => Promise<void> },
    ) {
      commands.set(name, command);
    },
  };
  sandboxExtension(pi as any);
  return { handlers, commands, pi };
}

async function emit(
  harness: ExtensionHarness,
  name: string,
  event: unknown,
  ctx: unknown,
): Promise<void> {
  for (const handler of harness.handlers.get(name) ?? []) await handler(event, ctx);
}

function writePolicies(projectRoot: string, agentDir: string, marker: string) {
  mkdirSync(join(projectRoot, ".pi"), { recursive: true });
  mkdirSync(agentDir, { recursive: true });
  const readPath = join(homedir(), `.pi-sandbox-lifecycle-${marker}-read`);
  const writePath = join(homedir(), `.pi-sandbox-lifecycle-${marker}-write`);
  const domain = `${marker}.packages.example.internal`;
  writeFileSync(
    join(agentDir, "sandbox.json"),
    JSON.stringify({
      policyVersion: 2,
      network: { allowedDomains: [], deniedDomains: [] },
      filesystem: {
        readScope: "strict",
        denyRead: [],
        allowRead: [],
        allowWrite: [],
        denyWrite: [],
      },
    }),
  );
  writeFileSync(
    join(projectRoot, ".pi", "sandbox.json"),
    JSON.stringify({
      policyVersion: 2,
      network: { allowedDomains: [domain], deniedDomains: [] },
      filesystem: {
        denyRead: [],
        allowRead: [readPath],
        allowWrite: [writePath],
        denyWrite: [],
      },
    }),
  );
  return { readPath, writePath, domain };
}

function createContext(
  projectRoot: string,
  options: {
    hasUI: boolean;
    mode: "tui" | "json" | "rpc";
    selections?: string[];
    events: string[];
    notifications: string[];
  },
) {
  return {
    cwd: projectRoot,
    hasUI: options.hasUI,
    mode: options.mode,
    isProjectTrusted: () => true,
    ui: {
      theme: { fg: (_color: string, text: string) => text },
      setStatus() {},
      notify(message: string) {
        options.notifications.push(message);
      },
      async select() {
        options.events.push("select");
        const selection = options.selections?.shift();
        if (!selection) throw new Error("Unexpected lifecycle selection prompt");
        return selection;
      },
    },
  };
}

test("session startup reviews and persists project requests before runtime initialization", async (t) => {
  const projectRoot = mkdtempSync(join(tmpdir(), "pi-sandbox-lifecycle-project-"));
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-lifecycle-agent-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  const previousNodeProxy = process.env.NODE_USE_ENV_PROXY;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  const marker = `approved-${process.pid}`;
  const requested = writePolicies(projectRoot, agentDir, marker);
  const events: string[] = [];
  const notifications: string[] = [];
  let runtimeConfig: SandboxRuntimeConfig | undefined;
  t.mock.method(SandboxManager, "initialize", async (config: SandboxRuntimeConfig) => {
    events.push("initialize");
    runtimeConfig = config;
  });

  try {
    const harness = createExtensionHarness();
    const ctx = createContext(projectRoot, {
      hasUI: true,
      mode: "tui",
      selections: ["Approve all for this project", "Confirm approval"],
      events,
      notifications,
    });
    await emit(harness, "session_start", { reason: "startup" }, ctx);

    assert.deepEqual(events, ["select", "select", "initialize"]);
    assert.ok(runtimeConfig);
    assert.equal(runtimeConfig.filesystem?.allowRead?.includes(requested.readPath), true);
    assert.equal(runtimeConfig.filesystem?.allowRead?.includes(requested.writePath), true);
    assert.equal(runtimeConfig.filesystem?.allowWrite?.includes(requested.writePath), true);
    assert.equal(runtimeConfig.network?.allowedDomains?.includes(requested.domain), true);

    const approvalPath = getConfigPaths(projectRoot).projectRequestApprovalPath;
    assert.equal(existsSync(approvalPath), true);
    const approval = JSON.parse(readFileSync(approvalPath, "utf-8"));
    assert.deepEqual(approval.approved, {
      read: [requested.readPath],
      write: [requested.writePath],
      network: [requested.domain],
    });

    await harness.commands.get("sandbox")?.handler("", ctx);
    assert.match(notifications.at(-1) ?? "", /status: previously-approved/);
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
    if (previousNodeProxy === undefined) delete process.env.NODE_USE_ENV_PROXY;
    else process.env.NODE_USE_ENV_PROXY = previousNodeProxy;
    rmSync(projectRoot, { recursive: true, force: true });
    rmSync(agentDir, { recursive: true, force: true });
  }
});

test("RPC startup defers project review and blocks bash until initialization", async (t) => {
  const projectRoot = mkdtempSync(join(tmpdir(), "pi-sandbox-lifecycle-project-"));
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-lifecycle-agent-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  const previousNodeProxy = process.env.NODE_USE_ENV_PROXY;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  writePolicies(projectRoot, agentDir, `rpc-${process.pid}`);
  const events: string[] = [];
  const notifications: string[] = [];
  t.mock.method(SandboxManager, "initialize", async () => {
    events.push("initialize");
  });

  try {
    const harness = createExtensionHarness();
    const ctx = createContext(projectRoot, {
      hasUI: true,
      mode: "rpc",
      selections: ["Approve all for this project", "Confirm approval"],
      events,
      notifications,
    });

    await emit(harness, "session_start", { reason: "startup" }, ctx);
    assert.equal(events.length, 0);

    const userBash = harness.handlers.get("user_bash")?.[0];
    assert.ok(userBash);
    const blocked = (await userBash({ type: "user_bash", command: "pwd" }, ctx)) as any;
    assert.equal(blocked.result.exitCode, 126);
    assert.match(blocked.result.output, /sandbox state is initializing/);

    const deadline = Date.now() + 2000;
    while (!events.includes("initialize") && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.deepEqual(events, ["select", "select", "initialize"]);
    assert.equal(existsSync(getConfigPaths(projectRoot).projectRequestApprovalPath), true);
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
    if (previousNodeProxy === undefined) delete process.env.NODE_USE_ENV_PROXY;
    else process.env.NODE_USE_ENV_PROXY = previousNodeProxy;
    rmSync(projectRoot, { recursive: true, force: true });
    rmSync(agentDir, { recursive: true, force: true });
  }
});

test("non-interactive session startup initializes with pending project requests blocked", async (t) => {
  const projectRoot = mkdtempSync(join(tmpdir(), "pi-sandbox-lifecycle-project-"));
  const agentDir = mkdtempSync(join(tmpdir(), "pi-sandbox-lifecycle-agent-"));
  const previousAgentDir = process.env.PI_CODING_AGENT_DIR;
  const previousNodeProxy = process.env.NODE_USE_ENV_PROXY;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  const requested = writePolicies(projectRoot, agentDir, `blocked-${process.pid}`);
  const events: string[] = [];
  const notifications: string[] = [];
  let runtimeConfig: SandboxRuntimeConfig | undefined;
  t.mock.method(SandboxManager, "initialize", async (config: SandboxRuntimeConfig) => {
    events.push("initialize");
    runtimeConfig = config;
  });

  try {
    const harness = createExtensionHarness();
    const ctx = createContext(projectRoot, {
      hasUI: false,
      mode: "json",
      events,
      notifications,
    });
    await emit(harness, "session_start", { reason: "startup" }, ctx);

    assert.deepEqual(events, ["initialize"]);
    assert.ok(runtimeConfig);
    assert.equal(runtimeConfig.filesystem?.allowRead?.includes(requested.readPath), false);
    assert.equal(runtimeConfig.filesystem?.allowWrite?.includes(requested.writePath), false);
    assert.equal(runtimeConfig.network?.allowedDomains?.includes(requested.domain), false);
    assert.match(notifications.join("\n"), /never auto-approve/);
    assert.equal(existsSync(getConfigPaths(projectRoot).projectRequestApprovalPath), false);
  } finally {
    if (previousAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
    else process.env.PI_CODING_AGENT_DIR = previousAgentDir;
    if (previousNodeProxy === undefined) delete process.env.NODE_USE_ENV_PROXY;
    else process.env.NODE_USE_ENV_PROXY = previousNodeProxy;
    rmSync(projectRoot, { recursive: true, force: true });
    rmSync(agentDir, { recursive: true, force: true });
  }
});
