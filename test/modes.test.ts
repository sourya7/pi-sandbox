import test from "node:test";

import assert from "node:assert/strict";

import { getLegacyModePolicy, parseOtherwiseAction, validateModeName } from "../src/modes.ts";

test("mode names accept arbitrary safe profile names", () => {
  for (const name of ["default", "restricted", "read-only", "audit_2"]) {
    assert.equal(validateModeName(name), name);
  }
});

test("mode names reject empty names and path-like input", () => {
  for (const name of ["", ".hidden", "../restricted", "foo/bar", "UPPER", "name.json"]) {
    assert.throws(() => validateModeName(name), /invalid sandbox mode/i);
  }
});

test("otherwise actions accept only prompt or deny", () => {
  assert.equal(parseOtherwiseAction("prompt", "filesystem.read.otherwise"), "prompt");
  assert.equal(parseOtherwiseAction("deny", "network.otherwise"), "deny");
  assert.throws(
    () => parseOtherwiseAction("allow", "filesystem.write.otherwise"),
    /filesystem\.write\.otherwise must be prompt or deny/,
  );
  assert.throws(
    () => parseOtherwiseAction(undefined, "network.otherwise"),
    /network\.otherwise must be prompt or deny/,
  );
});

test("legacy compatibility is limited to built-in v2 modes", () => {
  assert.equal(getLegacyModePolicy("default")?.write, "prompt");
  assert.equal(getLegacyModePolicy("read-only")?.write, "deny");
  assert.equal(getLegacyModePolicy("build")?.write, "prompt");
  assert.equal(getLegacyModePolicy("restricted"), undefined);
});
