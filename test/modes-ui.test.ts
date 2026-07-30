import test from "node:test";

import assert from "node:assert/strict";

import {
  classifyProjectAccessRequests,
  normalizeProjectAccessRequests,
} from "../src/access-requests.ts";
import { DEFAULT_CONFIG } from "../src/config.ts";
import { getModePolicy } from "../src/modes.ts";
import {
  formatProjectAccessRequestSummary,
  formatSandboxStatus,
  promptProjectAccessRequests,
} from "../src/ui.ts";

test("mode policies define read-only writes as deny", () => {
  assert.equal(getModePolicy("default").write, "prompt");
  assert.equal(getModePolicy("read-only").write, "deny");
  assert.equal(getModePolicy("build").write, "prompt");
  assert.deepEqual(getModePolicy("unknown"), getModePolicy("default"));
});

test("sandbox status includes active mode and write policy", () => {
  assert.match(formatSandboxStatus(DEFAULT_CONFIG, "build"), /Sandbox: build/);
  assert.match(formatSandboxStatus(DEFAULT_CONFIG, "build"), /write paths/);
  assert.match(formatSandboxStatus(DEFAULT_CONFIG, "read-only"), /Sandbox: read-only/);
  assert.match(formatSandboxStatus(DEFAULT_CONFIG, "read-only"), /writes denied/);
});

function pendingRequestState() {
  const root = "/project";
  const requests = normalizeProjectAccessRequests(
    {
      readPaths: [
        {
          value: "/external/read",
          sourcePath: "/project/.pi/sandbox.json",
          sourceKind: "project-base",
        },
      ],
      writePaths: [
        {
          value: "/external/write",
          sourcePath: "/project/.pi/sandbox.json",
          sourceKind: "project-base",
        },
      ],
      domains: [
        {
          value: "packages.example.internal",
          sourcePath: "/project/.pi/sandbox.json",
          sourceKind: "project-base",
        },
      ],
    },
    root,
  );
  const config = structuredClone(DEFAULT_CONFIG);
  config.filesystem.readScope = "strict";
  config.network = { allowedDomains: [], deniedDomains: [] };
  return classifyProjectAccessRequests({
    requests,
    config,
    projectRoot: root,
    mode: "default",
    modePolicy: getModePolicy("default"),
    protectedWritePaths: [],
  });
}

test("project request review summary groups pending capabilities", () => {
  const summary = formatProjectAccessRequestSummary(pendingRequestState());
  assert.match(summary, /Read:\n  \/external\/read/);
  assert.match(summary, /Write \(also grants read\):\n  \/external\/write/);
  assert.match(summary, /Network:\n  packages\.example\.internal/);
});

test("project request review never approves without an interactive UI", async () => {
  let selected = false;
  const ctx = {
    hasUI: false,
    mode: "json",
    ui: {
      select: async () => {
        selected = true;
        return "Approve all for this project";
      },
    },
  } as any;
  const result = await promptProjectAccessRequests(ctx, pendingRequestState());
  assert.equal(selected, false);
  assert.deepEqual(result, {
    action: "continue",
    approved: { read: [], write: [], network: [] },
  });
});

test("approve-all project review requires confirmation and returns pending capabilities", async () => {
  const selections = ["Approve all for this project", "Confirm approval"];
  const ctx = {
    hasUI: true,
    mode: "interactive",
    ui: { select: async () => selections.shift() },
  } as any;
  const result = await promptProjectAccessRequests(ctx, pendingRequestState());
  assert.deepEqual(result, {
    action: "continue",
    approved: {
      read: ["/external/read"],
      write: ["/external/write"],
      network: ["packages.example.internal"],
    },
  });
});
