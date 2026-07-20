import { spawn } from "node:child_process";
import { constants, existsSync, accessSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

import {
  SandboxManager,
  type SandboxAskCallback,
  type SandboxRuntimeConfig,
} from "@anthropic-ai/sandbox-runtime";
import { type BashOperations, getShellConfig } from "@earendil-works/pi-coding-agent";

import { type SandboxConfig } from "./config.ts";
import { domainIsAllowed } from "./policy.ts";

export interface SessionAllowances {
  domains: string[];
  readPaths: string[];
  writePaths: string[];
}

export function createNetworkAskCallback(
  allowedDomains: string[],
  onBlockedDomain?: (host: string) => Promise<boolean>,
): SandboxAskCallback {
  return async ({ host }) => {
    if (domainIsAllowed(host, allowedDomains)) return true;
    return onBlockedDomain ? onBlockedDomain(host) : false;
  };
}

function resolveConfigPath(pattern: string, cwd: string): string {
  if (pattern.startsWith("~")) return resolve(pattern.replace(/^~(?=$|\/)/, homedir()));
  if (isAbsolute(pattern)) return resolve(pattern);
  return resolve(join(cwd, pattern));
}

function deepestExistingAncestor(path: string): string | null {
  let current = dirname(path);
  while (current && current !== dirname(current)) {
    if (existsSync(current)) return current;
    current = dirname(current);
  }
  return existsSync(current) ? current : null;
}

function isWritable(path: string): boolean {
  try {
    accessSync(path, constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

export function filterDenyWriteForRuntime(denyWrite: string[], cwd: string): string[] {
  return denyWrite.filter((pattern) => {
    if (pattern.includes("*")) return true;
    const resolved = resolveConfigPath(pattern, cwd);
    if (existsSync(resolved)) return true;
    const ancestor = deepestExistingAncestor(resolved);
    return !ancestor || isWritable(ancestor);
  });
}

export function buildRuntimeConfig(
  config: SandboxConfig,
  allowances?: SessionAllowances,
  cwd?: string,
): SandboxRuntimeConfig {
  const denyWrite = config.filesystem?.denyWrite ?? [];
  return {
    network: {
      ...config.network,
      allowedDomains: [...(config.network?.allowedDomains ?? []), ...(allowances?.domains ?? [])],
      deniedDomains: config.network?.deniedDomains ?? [],
    },
    filesystem: {
      ...config.filesystem,
      denyRead: config.filesystem?.denyRead ?? [],
      allowRead: [...(config.filesystem?.allowRead ?? []), ...(allowances?.readPaths ?? [])],
      allowWrite: [...(config.filesystem?.allowWrite ?? []), ...(allowances?.writePaths ?? [])],
      denyWrite: cwd ? filterDenyWriteForRuntime(denyWrite, cwd) : denyWrite,
    },
    ignoreViolations: config.ignoreViolations,
    enableWeakerNestedSandbox: config.enableWeakerNestedSandbox,
    enableWeakerNetworkIsolation: true,
  };
}

export async function initializeSandbox(
  config: SandboxConfig,
  allowances?: SessionAllowances,
  cwd?: string,
  onBlockedDomain?: (host: string) => Promise<boolean>,
): Promise<void> {
  const runtimeConfig = buildRuntimeConfig(config, allowances, cwd);
  await SandboxManager.initialize(
    runtimeConfig,
    createNetworkAskCallback(runtimeConfig.network?.allowedDomains ?? [], onBlockedDomain),
    true,
  );
}

export async function reinitializeSandbox(
  config: SandboxConfig,
  allowances: SessionAllowances,
  cwd?: string,
  onBlockedDomain?: (host: string) => Promise<boolean>,
): Promise<void> {
  await SandboxManager.reset();
  await initializeSandbox(config, allowances, cwd, onBlockedDomain);
}

export function supportsNodeEnvProxy(version: string): boolean {
  const [major, minor] = version.split(".").map(Number);
  return (major === 22 && minor >= 21) || major >= 24;
}

export type ParsedSandboxViolation =
  | { type: "read"; path: string; raw: string }
  | { type: "write"; path: string; raw: string }
  | { type: "network"; host?: string; raw: string }
  | { type: "unknown"; raw: string };

function parseViolationLine(line: string): ParsedSandboxViolation | null {
  const trimmed = line.trim();
  const match = trimmed.match(/^deny(?:\(\d+\))?\s+(\S+)\s+(.+?)\s*$/);
  if (!match) return null;

  const [, op, target] = match;
  if (op.startsWith("file-read")) return { type: "read", path: target, raw: trimmed };
  if (op.startsWith("file-write")) return { type: "write", path: target, raw: trimmed };
  if (op === "network-outbound") {
    const host =
      target.match(/"([^"\s:)]+)(?::\d+)?"/)?.[1] ??
      target.match(/\b(?:host|ip)\s+([^"\s:)]+)/)?.[1];
    return { type: "network", host, raw: trimmed };
  }

  // Linux's violation monitor currently reports write-intent syscalls as
  // `deny <syscall> <path>`, for example `deny openat /tmp/file`.
  if (target.startsWith("/")) return { type: "write", path: target, raw: trimmed };
  return { type: "unknown", raw: trimmed };
}

export function extractSandboxViolation(output: string): ParsedSandboxViolation | null {
  const blockMatch = output.match(/<sandbox_violations>\s*([\s\S]*?)\s*<\/sandbox_violations>/m);
  if (blockMatch) {
    for (const line of blockMatch[1].split(/\r?\n/)) {
      const parsed = parseViolationLine(line);
      if (parsed) return parsed;
    }
  }

  // Shell redirection/create failures are write failures.
  const shellErrorMatch = output.match(
    /(?:^|\n)(?:(?:[^\n:]*\/)?(?:ba|z|fi)?sh): (?:line \d+: )?(.+?): (?:Operation not permitted|Read-only file system|Permission denied)(?:\n|$)/,
  );
  if (shellErrorMatch) {
    return { type: "write", path: shellErrorMatch[1], raw: shellErrorMatch[0].trim() };
  }

  // Common read tools report denied file reads as `<tool>: <path>: denied`.
  const readErrorMatch = output.match(
    /(?:^|\n)(?:cat|grep|rg|head|tail|less|more|sed|awk): (.+?): (?:Operation not permitted|Permission denied)(?:\n|$)/,
  );
  if (readErrorMatch) {
    return { type: "read", path: readErrorMatch[1], raw: readErrorMatch[0].trim() };
  }

  return null;
}

export function extractBlockedReadPath(output: string): string | null {
  const violation = extractSandboxViolation(output);
  return violation?.type === "read" ? violation.path : null;
}

export function extractBlockedWritePath(output: string): string | null {
  const violation = extractSandboxViolation(output);
  return violation?.type === "write" ? violation.path : null;
}

export function createSandboxedBashOps(shellPath?: string): BashOperations {
  return {
    async exec(command, cwd, { onData, signal, timeout, env }) {
      if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);

      const { shell, args } = getShellConfig(shellPath);
      const wrappedCommand = await SandboxManager.wrapWithSandbox(command, shell);

      return new Promise((resolve, reject) => {
        const child = spawn(shell, [...args, wrappedCommand], {
          cwd,
          env,
          detached: true,
          stdio: ["ignore", "pipe", "pipe"],
        });

        let timedOut = false;
        let timeoutHandle: NodeJS.Timeout | undefined;

        const killProcessGroup = () => {
          if (!child.pid) return;
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            child.kill("SIGKILL");
          }
        };

        if (timeout !== undefined && timeout > 0) {
          timeoutHandle = setTimeout(() => {
            timedOut = true;
            killProcessGroup();
          }, timeout * 1000);
        }

        let stderr = "";

        child.stdout?.on("data", onData);
        child.stderr?.on("data", (data: Buffer) => {
          stderr += data.toString("utf8");
          onData(data);
        });
        child.on("error", (error) => {
          if (timeoutHandle) clearTimeout(timeoutHandle);
          reject(error);
        });

        signal?.addEventListener("abort", killProcessGroup, { once: true });
        child.on("close", (code) => {
          if (timeoutHandle) clearTimeout(timeoutHandle);
          signal?.removeEventListener("abort", killProcessGroup);

          const annotatedStderr = SandboxManager.annotateStderrWithSandboxFailures(command, stderr);
          if (annotatedStderr !== stderr) {
            onData(Buffer.from(annotatedStderr.slice(stderr.length), "utf8"));
          }

          SandboxManager.cleanupAfterCommand();

          if (signal?.aborted) reject(new Error("aborted"));
          else if (timedOut) reject(new Error(`timeout:${timeout}`));
          else resolve({ exitCode: code });
        });
      });
    },
  };
}
