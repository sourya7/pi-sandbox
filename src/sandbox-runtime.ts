import { spawn } from "node:child_process";
import { existsSync } from "node:fs";

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

export function createNetworkAskCallback(allowedDomains: string[]): SandboxAskCallback {
  return async ({ host }) => domainIsAllowed(host, allowedDomains);
}

export function buildRuntimeConfig(
  config: SandboxConfig,
  allowances?: SessionAllowances,
): SandboxRuntimeConfig {
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
      denyWrite: config.filesystem?.denyWrite ?? [],
    },
    ignoreViolations: config.ignoreViolations,
    enableWeakerNestedSandbox: config.enableWeakerNestedSandbox,
    enableWeakerNetworkIsolation: true,
  };
}

export async function initializeSandbox(
  config: SandboxConfig,
  allowances?: SessionAllowances,
): Promise<void> {
  const runtimeConfig = buildRuntimeConfig(config, allowances);
  await SandboxManager.initialize(
    runtimeConfig,
    createNetworkAskCallback(runtimeConfig.network?.allowedDomains ?? []),
    true,
  );
}

export async function reinitializeSandbox(
  config: SandboxConfig,
  allowances: SessionAllowances,
): Promise<void> {
  await SandboxManager.reset();
  await initializeSandbox(config, allowances);
}

export function supportsNodeEnvProxy(version: string): boolean {
  const [major, minor] = version.split(".").map(Number);
  return (major === 22 && minor >= 21) || major >= 24;
}

export function extractBlockedWritePath(output: string): string | null {
  const violationMatch = output.match(
    /<sandbox_violations>\s*[\s\S]*?^deny\s+\S+\s+(.+?)\s*$[\s\S]*?<\/sandbox_violations>/m,
  );
  if (violationMatch) return violationMatch[1];

  const shellErrorMatch = output.match(
    /(?:^|\n)(?:(?:[^\n:]*\/)?(?:ba|z|fi)?sh): (?:line \d+: )?(.+?): (?:Operation not permitted|Read-only file system|Permission denied)(?:\n|$)/,
  );
  return shellErrorMatch ? shellErrorMatch[1] : null;
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
