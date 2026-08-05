import { mkdtempSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import assert from "node:assert/strict";

import { DEFAULT_CONFIG, type SandboxConfig } from "../src/config.ts";
import {
  canAuthorizeSessionGrant,
  classifyExactSessionOverride,
  deriveConfigWithExactOverrides,
  formatSessionGrantConfirmation,
  overrideAllowances,
  type ExactSessionOverride,
} from "../src/session-overrides.ts";

function config(filesystem: Partial<SandboxConfig["filesystem"]>): SandboxConfig {
  return {
    ...DEFAULT_CONFIG,
    filesystem: { ...DEFAULT_CONFIG.filesystem, denyWrite: [], ...filesystem },
  };
}

function override(operation: "read" | "write", canonicalPath: string): ExactSessionOverride {
  return {
    operation,
    configuredValue: canonicalPath,
    canonicalPath,
    removedRules: [],
    createdAt: new Date(0).toISOString(),
  };
}

test("classifies exact duplicate rules separately from broader coverage", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-override-"));
  try {
    const target = join(cwd, ".env");
    const exact = classifyExactSessionOverride({
      operation: "read",
      path: target,
      config: config({ denyRead: [".env", `${target}/**`] }),
      cwd,
    });
    assert.equal(exact.exactRules.length, 2);
    assert.deepEqual(exact.broaderRules, []);

    const nested = classifyExactSessionOverride({
      operation: "read",
      path: join(cwd, ".ssh", "known_hosts"),
      config: config({ denyRead: [".ssh"] }),
      cwd,
    });
    assert.deepEqual(nested.exactRules, []);
    assert.equal(nested.broaderRules[0]?.configuredValue, ".ssh");
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("canonical identities include relative, absolute, trailing subtree, and symlink spellings", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-override-link-"));
  const real = join(cwd, "real");
  const link = join(cwd, "link");
  mkdirSync(real);
  symlinkSync(real, link);
  try {
    const classified = classifyExactSessionOverride({
      operation: "read",
      path: real,
      config: config({ denyRead: ["real", `${link}/**`] }),
      cwd,
    });
    assert.equal(classified.exactRules.length, 2);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("write classification includes read/write denies and rejects final protections", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-override-write-"));
  try {
    const target = join(cwd, ".env");
    const classified = classifyExactSessionOverride({
      operation: "write",
      path: target,
      config: {
        ...config({ denyRead: [".env"], denyWrite: [".env"] }),
        credentials: { files: [{ path: ".env", mode: "deny" }] },
      },
      cwd,
      protectedWritePaths: [target],
    });
    assert.deepEqual(
      classified.exactRules.map((rule) => rule.field),
      ["denyRead", "denyWrite"],
    );
    assert.equal(classified.nonOverridableRules.length, 2);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("credential masks and mandatory write protections are non-overridable", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-override-protected-"));
  try {
    const masked = classifyExactSessionOverride({
      operation: "read",
      path: join(cwd, "token"),
      config: {
        ...config({ denyRead: ["token"] }),
        credentials: { files: [{ path: "token", mode: "mask" }] },
      },
      cwd,
    });
    assert.equal(masked.nonOverridableRules[0]?.source, "credential mask");

    const hook = classifyExactSessionOverride({
      operation: "write",
      path: join(cwd, ".git", "hooks", "pre-commit"),
      config: config({ denyWrite: [".git/hooks/pre-commit"] }),
      cwd,
    });
    assert.equal(hook.nonOverridableRules[0]?.source, "mandatory Git hooks directory");
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("deriveConfigWithExactOverrides removes only matching operation fields without mutation", () => {
  const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-derived-"));
  try {
    const original = config({
      denyRead: [".env", ".env.local", ".ssh"],
      denyWrite: [".env", ".env.local"],
    });
    const read = deriveConfigWithExactOverrides(
      original,
      [override("read", join(cwd, ".env"))],
      cwd,
    );
    assert.deepEqual(read.filesystem.denyRead, [".env.local", ".ssh"]);
    assert.deepEqual(read.filesystem.denyWrite, [".env", ".env.local"]);

    const write = deriveConfigWithExactOverrides(
      original,
      [override("write", join(cwd, ".env"))],
      cwd,
    );
    assert.deepEqual(write.filesystem.denyRead, [".env.local", ".ssh"]);
    assert.deepEqual(write.filesystem.denyWrite, [".env.local"]);
    assert.deepEqual(original.filesystem.denyRead, [".env", ".env.local", ".ssh"]);
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("override allowances make writes imply reads and deduplicate paths", () => {
  const path = "/tmp/example";
  assert.deepEqual(overrideAllowances([override("read", path), override("write", path)]), {
    readPaths: [path],
    writePaths: [path],
  });
});

test("only TUI and RPC UI contexts can authorize slash-command grants", () => {
  assert.equal(canAuthorizeSessionGrant("tui", true), true);
  assert.equal(canAuthorizeSessionGrant("rpc", true), true);
  assert.equal(canAuthorizeSessionGrant("json", false), false);
  assert.equal(canAuthorizeSessionGrant("print", false), false);
  assert.equal(canAuthorizeSessionGrant("rpc", false), false);
});

test("confirmation text exposes canonical capability and removed rules", () => {
  const confirmation = formatSessionGrantConfirmation({
    operation: "read",
    mode: "default",
    classification: {
      canonicalPath: "/project/.env",
      exactRules: [{ field: "denyRead", configuredValue: ".env" }],
      broaderRules: [],
      nonOverridableRules: [],
    },
  });
  assert.match(confirmation.title, /read access/);
  assert.match(confirmation.message, /Path: \/project\/\.env/);
  assert.match(confirmation.message, /denyRead \.env/);
  assert.match(confirmation.message, /Mode: default/);
  assert.match(confirmation.message, /agent tools and sandboxed commands/);
  assert.match(confirmation.message, /active mode and session/);
});
