import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import { hasOtherProjectTrustResources, hasProjectSandboxDeclaration } from "../src/extension.ts";

test("sandbox-only project configuration is detected as a trust trigger", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-trust-"));
  mkdirSync(join(cwd, ".pi"));
  writeFileSync(join(cwd, ".pi", "sandbox.json"), "{}");
  assert.equal(hasProjectSandboxDeclaration(cwd), true);
  assert.equal(hasOtherProjectTrustResources(cwd), false);
});

test("mode-only sandbox declarations are detected", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-trust-"));
  mkdirSync(join(cwd, ".pi"));
  writeFileSync(join(cwd, ".pi", "sandbox.read-only.json"), "{}");
  assert.equal(hasProjectSandboxDeclaration(cwd), true);
});

test("existing Pi resources defer to Pi's built-in trust flow", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-trust-"));
  mkdirSync(join(cwd, ".pi"));
  writeFileSync(join(cwd, ".pi", "sandbox.json"), "{}");
  writeFileSync(join(cwd, ".pi", "settings.json"), "{}");
  assert.equal(hasOtherProjectTrustResources(cwd), true);
});

test("ancestor agent skills defer to Pi's built-in trust flow", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-trust-"));
  const cwd = join(root, "nested", "project");
  mkdirSync(join(root, ".agents", "skills"), { recursive: true });
  mkdirSync(cwd, { recursive: true });
  assert.equal(hasOtherProjectTrustResources(cwd), true);
});
