import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";

import {
  SandboxManager,
  type SandboxAskCallback,
  type SandboxRuntimeConfig,
} from "@anthropic-ai/sandbox-runtime";
import { type BashOperations, getShellConfig } from "@earendil-works/pi-coding-agent";

import { type SandboxConfig } from "./config.ts";
import {
  canonicalizePath,
  domainIsAllowed,
  resolveLexicalPath,
  resolvePolicyPatterns,
} from "./policy.ts";

export interface SessionAllowances {
  domains: string[];
  readPaths: string[];
  writePaths: string[];
}

export function createNetworkAskCallback(
  allowedDomains: string[],
  onBlockedDomain?: (destination: string) => Promise<boolean>,
): SandboxAskCallback {
  return async ({ host, port }) => {
    if (domainIsAllowed(host, allowedDomains, port)) return true;
    const destination =
      port === undefined ? host : `${host.includes(":") ? `[${host}]` : host}:${port}`;
    return onBlockedDomain ? onBlockedDomain(destination) : false;
  };
}

function resolveConfigPath(pattern: string, cwd: string): string {
  if (pattern.startsWith("~")) return resolve(pattern.replace(/^~(?=$|\/)/, homedir()));
  if (isAbsolute(pattern)) return resolve(pattern);
  return resolve(join(cwd, pattern));
}

function pathIsWithin(path: string, ancestor: string): boolean {
  return path === ancestor || ancestor === "/" || path.startsWith(`${ancestor}/`);
}

function withoutSubtree(pattern: string): string {
  return pattern.endsWith("/**") ? pattern.slice(0, -3) || "/" : pattern;
}

export interface RuntimeProtectedWritePathResolution {
  runtimePaths: string[];
  deferredPaths: string[];
}

/** Derive mountable Linux protection targets from the immutable logical policy
 * paths. Only the immediate policy directory may substitute for an absent
 * policy file; falling back to a broader existing ancestor could freeze the
 * project root or home directory. */
export function resolveRuntimeProtectedWritePaths(
  protectedPaths: string[],
  cwd: string,
  platform: NodeJS.Platform = process.platform,
): RuntimeProtectedWritePathResolution {
  const logicalPaths = [...new Set(protectedPaths.map((path) => canonicalizePath(path, cwd)))];
  if (platform !== "linux") return { runtimePaths: logicalPaths, deferredPaths: [] };

  const candidates: string[] = [];
  const deferredPaths: string[] = [];
  for (const path of logicalPaths) {
    if (existsSync(path)) {
      candidates.push(canonicalizePath(path, cwd));
      continue;
    }
    const parent = dirname(path);
    if (existsSync(parent)) candidates.push(canonicalizePath(parent, cwd));
    else deferredPaths.push(path);
  }
  const runtimePaths = removeRedundantDescendants([...new Set(candidates)]);
  return { runtimePaths, deferredPaths };
}

/** Linux cannot safely mount an absent deny target below a writable path.
 * Such a configured hard deny must fail closed rather than being silently
 * removed. An absent target outside all effective writes is redundant. */
export function filterDenyWriteForRuntime(
  denyWrite: string[],
  writePaths: string[],
  cwd: string,
  platform: NodeJS.Platform = process.platform,
): string[] {
  if (platform !== "linux") return denyWrite;
  const resolvedWrites = uniquePaths(writePaths, cwd);
  return denyWrite.filter((pattern) => {
    const raw = withoutSubtree(pattern);
    const lexical = resolveConfigPath(raw, cwd);
    if (existsSync(lexical)) return true;
    const resolved = canonicalizePath(raw, cwd);
    const coveringWrite = resolvedWrites.find((writePath) => pathIsWithin(resolved, writePath));
    if (coveringWrite) {
      throw new Error(
        `Cannot enforce nonexistent deny-write path "${resolved}" beneath writable path "${coveringWrite}" with the installed Linux sandbox runtime. Create the target before startup, narrow filesystem.write.allow, or remove the deny rule.`,
      );
    }
    return false;
  });
}

export function getRuntimeBootstrapReadPaths(cwd: string, strict: boolean): string[] {
  const candidates = new Set<string>();
  if (strict) {
    // Add broad roots before nested executables. Upstream emits allowRead binds
    // in input order; a nested bind cannot be created after its parent is masked
    // unless the broad parent has already been restored.
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
  candidates.add(process.execPath);
  const shell = process.env.SHELL;
  if (shell) candidates.add(shell);
  const resolved = [...candidates].map((path) => canonicalizePath(path, cwd));
  return resolved.filter(
    (path, index) =>
      !resolved.some(
        (ancestor, ancestorIndex) =>
          ancestorIndex < index &&
          ancestor !== path &&
          (ancestor === "/" || path.startsWith(`${ancestor}/`)),
      ),
  );
}

function uniquePaths(paths: string[], cwd: string): string[] {
  return [...new Set(resolvePolicyPatterns(paths, cwd).map((path) => path.replace(/\/\*\*$/, "")))];
}

function removeRedundantDescendants(paths: string[]): string[] {
  return paths.filter(
    (path) =>
      !paths.some(
        (ancestor) => ancestor !== path && (ancestor === "/" || path.startsWith(`${ancestor}/`)),
      ),
  );
}

/** Preserve the configured spelling as well as its canonical target. The
 * runtime needs the lexical spelling to restore explicitly allowed symlink
 * aliases inside a masked read scope. */
function uniqueLexicalPaths(paths: string[], cwd: string): string[] {
  return [
    ...new Set(
      paths.map((path) => {
        const subtree = path.endsWith("/**");
        const raw = subtree ? path.slice(0, -3) || "/" : path;
        return resolveLexicalPath(raw, cwd);
      }),
    ),
  ];
}

export function buildRuntimeConfig(
  config: SandboxConfig,
  allowances?: SessionAllowances,
  cwd = process.cwd(),
  protectedWritePaths: string[] = [],
  additionalBootstrapReadPaths: string[] = [],
): SandboxRuntimeConfig {
  const filesystem = config.filesystem;
  const readScope = filesystem.readScope ?? "home";
  const writePaths = uniquePaths(
    [...filesystem.allowWrite, ...(allowances?.writePaths ?? [])],
    cwd,
  );
  const readInputs = [
    ...(filesystem.allowRead ?? []),
    ...(allowances?.readPaths ?? []),
    ...filesystem.allowWrite,
    ...(allowances?.writePaths ?? []),
  ];
  const configuredRead = [
    ...new Set([...uniquePaths(readInputs, cwd), ...uniqueLexicalPaths(readInputs, cwd)]),
  ];
  const bootstrap = removeRedundantDescendants([
    ...getRuntimeBootstrapReadPaths(cwd, readScope === "strict"),
    ...uniquePaths(additionalBootstrapReadPaths, cwd),
    ...uniqueLexicalPaths(additionalBootstrapReadPaths, cwd),
  ]);
  const scopeDeny = readScope === "strict" ? ["/"] : readScope === "home" ? [homedir()] : [];
  const credentialHardRead = uniquePaths(
    (config.credentials?.files ?? [])
      .filter((entry) => entry.mode === "deny")
      .map((entry) => entry.path),
    cwd,
  );
  const hardRead = uniquePaths([...filesystem.denyRead, ...credentialHardRead], cwd);
  const configuredDenyWrite = filterDenyWriteForRuntime(filesystem.denyWrite, writePaths, cwd);
  const hardReadWriteProtection = filterDenyWriteForRuntime(hardRead, writePaths, cwd);
  const runtimeProtection = resolveRuntimeProtectedWritePaths(protectedWritePaths, cwd);
  const denyWrite = uniquePaths(
    [...configuredDenyWrite, ...hardReadWriteProtection, ...runtimeProtection.runtimePaths],
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
      // Upstream keeps a deny that is more specific than an enclosing allow.
      // Put hard denies alongside the broad scope deny so /project/secret stays
      // denied while /project is re-opened by allowRead.
      denyRead: [...new Set([...scopeDeny, ...hardRead])],
      allowRead: [...new Set([...configuredRead, ...bootstrap])],
      allowWrite: writePaths,
      denyWrite,
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

const EXIT_STDIO_GRACE_MS = 100;

/** Wait for the direct child without hanging forever when a detached
 * descendant inherits its pipes. Output that remains active gets a fresh
 * grace period after every chunk. */
function waitForChildProcess(child: ChildProcess): Promise<number | null> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let exited = false;
    let exitCode: number | null = null;
    let timer: NodeJS.Timeout | undefined;
    let stdoutEnded = child.stdout === null;
    let stderrEnded = child.stderr === null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      child.removeListener("error", onError);
      child.removeListener("exit", onExit);
      child.removeListener("close", onClose);
      child.stdout?.removeListener("end", onStdoutEnd);
      child.stderr?.removeListener("end", onStderrEnd);
      child.stdout?.removeListener("data", onData);
      child.stderr?.removeListener("data", onData);
    };
    const finish = (code: number | null) => {
      if (settled) return;
      settled = true;
      cleanup();
      child.stdout?.destroy();
      child.stderr?.destroy();
      resolve(code);
    };
    const maybeFinish = () => {
      if (exited && stdoutEnded && stderrEnded) finish(exitCode);
    };
    const armTimer = () => {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => finish(exitCode), EXIT_STDIO_GRACE_MS);
    };
    const onData = () => {
      if (exited) armTimer();
    };
    const onStdoutEnd = () => {
      stdoutEnded = true;
      maybeFinish();
    };
    const onStderrEnd = () => {
      stderrEnded = true;
      maybeFinish();
    };
    const onError = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onExit = (code: number | null) => {
      exited = true;
      exitCode = code;
      maybeFinish();
      if (!settled) armTimer();
    };
    const onClose = (code: number | null) => finish(code);

    child.stdout?.once("end", onStdoutEnd);
    child.stderr?.once("end", onStderrEnd);
    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);
    child.once("error", onError);
    child.once("exit", onExit);
    child.once("close", onClose);
  });
}

export function createSandboxedBashOps(shellPath?: string): BashOperations {
  return {
    async exec(command, cwd, { onData, signal, timeout, env }) {
      if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);

      const { shell, args } = getShellConfig(shellPath);
      const commandId = randomUUID();
      const wrappedCommand = await SandboxManager.wrapWithSandbox(
        command,
        shell,
        undefined,
        signal,
        { commandId, commandText: command },
      );

      const child = spawn(shell, [...args, wrappedCommand], {
        cwd,
        env,
        detached: true,
        stdio: ["ignore", "pipe", "pipe"],
      });

      let timedOut = false;
      let timeoutHandle: NodeJS.Timeout | undefined;
      let stderr = "";
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
      child.stdout?.on("data", onData);
      child.stderr?.on("data", (data: Buffer) => {
        stderr += data.toString("utf8");
        onData(data);
      });
      signal?.addEventListener("abort", killProcessGroup, { once: true });

      try {
        const exitCode = await waitForChildProcess(child);
        // Linux observation is socket-driven and needs one event-loop turn;
        // macOS log-stream delivery needs a short bounded grace period.
        await new Promise<void>((done) =>
          process.platform === "darwin" ? setTimeout(done, 100) : setImmediate(done),
        );
        const annotatedStderr = SandboxManager.annotateStderrWithSandboxFailures(commandId, stderr);
        if (annotatedStderr !== stderr) {
          onData(Buffer.from(annotatedStderr.slice(stderr.length), "utf8"));
        }
        if (signal?.aborted) throw new Error("aborted");
        if (timedOut) throw new Error(`timeout:${timeout}`);
        return { exitCode };
      } finally {
        if (timeoutHandle) clearTimeout(timeoutHandle);
        signal?.removeEventListener("abort", killProcessGroup);
        SandboxManager.cleanupAfterCommand();
      }
    },
  };
}
