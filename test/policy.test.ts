import { mkdtempSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import {
  allowsAllDomains,
  canonicalizePath,
  domainIsAllowed,
  evaluateReadPolicy,
  hardDeniesWithin,
  matchesPattern,
  shouldPromptForWrite,
} from "../src/policy.ts";

test("matches exact, wildcard, and all-domain policies", () => {
  assert.equal(domainIsAllowed("github.com", ["github.com"]), true);
  assert.equal(domainIsAllowed("api.github.com", ["*.github.com"]), true);
  assert.equal(domainIsAllowed("notgithub.com", ["*.github.com"]), false);
  assert.equal(allowsAllDomains(["*"]), true);
});

test("empty allowWrite prompts securely", () => {
  assert.equal(shouldPromptForWrite("/tmp/file", [], matchesPattern), true);
  assert.equal(shouldPromptForWrite("/tmp/file", ["/tmp"], matchesPattern), false);
});

test("path patterns support directory prefixes and globs", () => {
  const root = canonicalizePath(mkdtempSync(join(tmpdir(), "pi-sandbox-policy-")));
  assert.equal(matchesPattern(join(root, "nested", "file.txt"), [root]), true);
  assert.equal(matchesPattern(join(root, "file.pem"), [join(root, "*.pem")]), true);
  assert.equal(matchesPattern(join(root, "file.txt"), [join(root, "*.pem")]), false);
});

test("portable trailing subtree syntax includes the directory and descendants", () => {
  const root = canonicalizePath(mkdtempSync(join(tmpdir(), "pi-sandbox-subtree-")));
  assert.equal(matchesPattern(root, [`${root}/**`]), true);
  assert.equal(matchesPattern(join(root, "nested", "file"), [`${root}/**`]), true);
});

test("relative policy patterns resolve against the supplied session cwd", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-cwd-"));
  assert.equal(matchesPattern(join(root, "src", "file.ts"), ["src"], root), true);
});

test("canonicalizes symlinks and nonexistent descendants", () => {
  const root = mkdtempSync(join(tmpdir(), "pi-sandbox-canonical-"));
  const real = join(root, "real");
  const link = join(root, "link");
  mkdirSync(real);
  symlinkSync(real, link);
  assert.equal(
    canonicalizePath(join(link, "new", "file")),
    join(canonicalizePath(real), "new", "file"),
  );
});

test("v2 read policy applies hard deny before allow and scope", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-read-policy-"));
  const common = {
    cwd,
    policyVersion: 2 as const,
    readScope: "strict" as const,
    denyRead: [join(cwd, "secret")],
    allowRead: [cwd],
    modeBehavior: "prompt" as const,
  };
  assert.equal(evaluateReadPolicy({ ...common, path: join(cwd, "secret", "key") }), "hard-deny");
  assert.equal(evaluateReadPolicy({ ...common, path: join(cwd, "source.ts") }), "allow");
  assert.equal(evaluateReadPolicy({ ...common, path: "/unlisted" }), "prompt");
});

test("open and home scopes allow paths outside their protected region", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-read-scope-"));
  assert.equal(
    evaluateReadPolicy({
      path: "/etc/hosts",
      cwd,
      policyVersion: 2,
      readScope: "open",
      denyRead: [],
      allowRead: [],
      modeBehavior: "prompt",
    }),
    "outside-scope-allow",
  );
});

test("home scope protects a home symlink even when its target is outside home", () => {
  const target = mkdtempSync(join(tmpdir(), "pi-sandbox-home-link-target-"));
  const container = mkdtempSync(join(homedir(), ".pi-sandbox-home-link-"));
  const link = join(container, "link");
  symlinkSync(target, link);
  try {
    const input = {
      path: link,
      cwd: container,
      policyVersion: 2 as const,
      readScope: "home" as const,
      denyRead: [],
      allowRead: [],
      modeBehavior: "prompt" as const,
    };
    assert.equal(evaluateReadPolicy(input), "prompt");
    assert.equal(evaluateReadPolicy({ ...input, allowRead: [link] }), "allow");
  } finally {
    rmSync(container, { recursive: true, force: true });
    rmSync(target, { recursive: true, force: true });
  }
});

test("recursive checks discover hard-denied descendants", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-recursive-"));
  assert.deepEqual(hardDeniesWithin(cwd, [join(cwd, "nested", "secret")], cwd), [
    join(cwd, "nested", "secret"),
  ]);
});
