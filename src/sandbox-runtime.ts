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
import { canonicalizePath, domainIsAllowed, resolvePolicyPatterns } from "./policy.ts";

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

export function getRuntimeBootstrapReadPaths(cwd: string, strict: boolean): string[] {
  const candidates = new Set<string>([process.execPath]);
  const shell = process.env.SHELL;
  if (shell) candidates.add(shell);
  if (strict) {
    const platformPaths =
      process.platform === "darwin"
        ? [
            "/bin",
            "/usr",
            "/System",
            "/Library",
            "/private",
            "/dev",
            "/Applications",
            "/opt/homebrew",
            "/opt/local",
            "/usr/local",
            "/nix",
            "/run",
          ]
        : ["/bin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", "/run", "/nix"];
    for (const path of platformPaths) if (existsSync(path)) candidates.add(path);
  }
  return [...candidates].map((path) => canonicalizePath(path, cwd));
}

function uniquePaths(paths: string[], cwd: string): string[] {
  return [...new Set(resolvePolicyPatterns(paths, cwd).map((path) => path.replace(/\/\*\*$/, "")))];
}

export function buildRuntimeConfig(
  config: SandboxConfig,
  allowances?: SessionAllowances,
  cwd = process.cwd(),
  protectedWritePaths: string[] = [],
  additionalBootstrapReadPaths: string[] = [],
): SandboxRuntimeConfig {
  const filesystem = config.filesystem;
  const version = config.policyVersion ?? 1;
  const readScope = filesystem.readScope ?? (version === 2 ? "home" : "open");
  const writePaths = uniquePaths(
    [...filesystem.allowWrite, ...(allowances?.writePaths ?? [])],
    cwd,
  );
  const configuredRead = uniquePaths(
    [...(filesystem.allowRead ?? []), ...(allowances?.readPaths ?? []), ...writePaths],
    cwd,
  );
  const bootstrap = [
    ...getRuntimeBootstrapReadPaths(cwd, readScope === "strict"),
    ...uniquePaths(additionalBootstrapReadPaths, cwd),
  ];
  const scopeDeny =
    version === 2
      ? readScope === "strict"
        ? ["/"]
        : readScope === "home"
          ? [homedir()]
          : []
      : uniquePaths(filesystem.denyRead, cwd);
  const credentialHardRead = uniquePaths(
    (config.credentials?.files ?? [])
      .filter((entry) => entry.mode === "deny")
      .map((entry) => entry.path),
    cwd,
  );
  const hardRead =
    version === 2
      ? uniquePaths([...filesystem.denyRead, ...credentialHardRead], cwd)
      : credentialHardRead;
  const denyWrite = uniquePaths(
    [...filesystem.denyWrite, ...hardRead, ...protectedWritePaths],
    cwd,
  );
  return {
    network: {
      ...config.network,
      allowedDomains: [...(config.network?.allowedDomains ?? []), ...(allowances?.domains ?? [])],
      deniedDomains: config.network?.deniedDomains ?? [],
    },
    filesystem: {
      disabled: filesystem.disabled,
      allowGitConfig: filesystem.allowGitConfig,
      denyRead: scopeDeny,
      allowRead: [...new Set([...configuredRead, ...bootstrap])],
      denyReadAlways: hardRead,
      allowWrite: writePaths,
      denyWrite: filterDenyWriteForRuntime(denyWrite, cwd),
    },
    credentials: config.credentials,
    ignoreViolations: config.ignoreViolations,
    enableWeakerNestedSandbox: config.enableWeakerNestedSandbox,
    enableWeakerNetworkIsolation: config.enableWeakerNetworkIsolation ?? false,
    allowPty: config.allowPty,
    allowAppleEvents: config.allowAppleEvents,
    ripgrep: config.ripgrep,
    mandatoryDenySearchDepth: config.mandatoryDenySearchDepth,
    seccomp: config.seccomp,
    bwrapPath: config.bwrapPath,
    socatPath: config.socatPath,
    windows: config.windows,
    git: config.git,
  };
}

export async function initializeSandbox(
  config: SandboxConfig,
  allowances?: SessionAllowances,
  cwd?: string,
  onBlockedDomain?: (host: string) => Promise<boolean>,
  protectedWritePaths: string[] = [],
  additionalBootstrapReadPaths: string[] = [],
): Promise<void> {
  const runtimeConfig = buildRuntimeConfig(
    config,
    allowances,
    cwd,
    protectedWritePaths,
    additionalBootstrapReadPaths,
  );
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
  protectedWritePaths: string[] = [],
  additionalBootstrapReadPaths: string[] = [],
): Promise<void> {
  await SandboxManager.reset();
  await initializeSandbox(
    config,
    allowances,
    cwd,
    onBlockedDomain,
    protectedWritePaths,
    additionalBootstrapReadPaths,
  );
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
      const violationCursor = SandboxManager.getSandboxViolationStore().getCursor();

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
          void (async () => {
            if (timeoutHandle) clearTimeout(timeoutHandle);
            signal?.removeEventListener("abort", killProcessGroup);

            try {
              await SandboxManager.waitForSandboxViolationDrain();
              const annotatedStderr = SandboxManager.annotateStderrWithSandboxFailures(
                command,
                stderr,
                violationCursor,
              );
              if (annotatedStderr !== stderr) {
                onData(Buffer.from(annotatedStderr.slice(stderr.length), "utf8"));
              }
            } finally {
              SandboxManager.cleanupAfterCommand();
            }

            if (signal?.aborted) reject(new Error("aborted"));
            else if (timedOut) reject(new Error(`timeout:${timeout}`));
            else resolve({ exitCode: code });
          })().catch(reject);
        });
      });
    },
  };
}
