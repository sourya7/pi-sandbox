import test from "node:test";

import assert from "node:assert/strict";

import { DEFAULT_CONFIG } from "../src/config.ts";
import { getModePolicy } from "../src/modes.ts";
import { formatSandboxStatus } from "../src/ui.ts";

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
