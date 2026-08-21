import test from "node:test";

import assert from "node:assert/strict";

import { getLegacyModePolicy, parseModePolicy, validateModeName } from "../src/modes.ts";

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

test("mode behavior requires explicit prompt or deny values", () => {
  assert.deepEqual(
    parseModePolicy({ read: "prompt", write: "deny", network: "prompt" }, "test mode"),
    { read: "prompt", write: "deny", network: "prompt" },
  );
  assert.throws(
    () => parseModePolicy({ read: "prompt", write: "allow", network: "prompt" }, "test mode"),
    /test mode: mode.write must be prompt or deny/,
  );
  assert.throws(
    () => parseModePolicy({ read: "prompt", write: "deny" }, "test mode"),
    /test mode: mode.network must be prompt or deny/,
  );
  assert.throws(
    () =>
      parseModePolicy(
        { read: "prompt", write: "deny", network: "prompt", typo: "deny" },
        "test mode",
      ),
    /test mode: unsupported mode field typo/,
  );
});

test("read deny requires write deny because writes imply reads", () => {
  assert.throws(
    () => parseModePolicy({ read: "deny", write: "prompt", network: "deny" }, "test mode"),
    /read deny requires write deny/,
  );
});

test("legacy compatibility is limited to built-in v2 modes", () => {
  assert.equal(getLegacyModePolicy("default")?.write, "prompt");
  assert.equal(getLegacyModePolicy("read-only")?.write, "deny");
  assert.equal(getLegacyModePolicy("build")?.write, "prompt");
  assert.equal(getLegacyModePolicy("restricted"), undefined);
});
