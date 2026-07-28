import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, resolve } from "node:path";

export type PathDecision = "hard-deny" | "mode-deny" | "allow" | "prompt" | "outside-scope-allow";

export interface ReadPolicyInput {
  path: string;
  cwd: string;
  readScope: "home" | "strict" | "open";
  denyRead: string[];
  allowRead: string[];
  modeBehavior: "prompt" | "deny";
}

export function shouldPromptForWrite(
  path: string,
  allowWrite: string[],
  matches: (path: string, patterns: string[]) => boolean,
): boolean {
  return allowWrite.length === 0 || !matches(path, allowWrite);
}

export function domainMatchesPattern(domain: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith("." + base);
  }
  return domain === pattern;
}

export function allowsAllDomains(allowedDomains: string[] | undefined): boolean {
  return allowedDomains?.includes("*") ?? false;
}

export function domainIsAllowed(domain: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((pattern) => domainMatchesPattern(domain, pattern));
}

export function resolveLexicalPath(filePath: string, cwd = process.cwd()): string {
  const expanded = filePath.replace(/^~(?=$|\/)/, homedir());
  return resolve(isAbsolute(expanded) ? expanded : resolve(cwd, expanded));
}

export function canonicalizePath(filePath: string, cwd = process.cwd()): string {
  const absolutePath = resolveLexicalPath(filePath, cwd);
  try {
    return realpathSync.native(absolutePath);
  } catch {
    const tail: string[] = [];
    let probe = absolutePath;
    while (!existsSync(probe)) {
      const parent = dirname(probe);
      if (parent === probe) return absolutePath;
      tail.unshift(basename(probe));
      probe = parent;
    }
    try {
      return resolve(realpathSync.native(probe), ...tail);
    } catch {
      return absolutePath;
    }
  }
}

function containsGlob(pattern: string): boolean {
  return ["*", "?", "[", "]"].some((character) => pattern.includes(character));
}

function staticGlobPrefix(pattern: string): string {
  const indexes = ["*", "?", "[", "]"]
    .map((character) => pattern.indexOf(character))
    .filter((index) => index >= 0);
  return indexes.length ? pattern.slice(0, Math.min(...indexes)) : pattern;
}

export function resolvePolicyPatterns(patterns: string[], cwd: string): string[] {
  return patterns.map((pattern) => {
    const subtree = pattern.endsWith("/**");
    const raw = subtree ? pattern.slice(0, -3) || "/" : pattern;
    if (containsGlob(raw)) return resolveLexicalPath(raw, cwd);
    const resolved = canonicalizePath(raw, cwd);
    return subtree ? `${resolved}/**` : resolved;
  });
}

function globRegex(absolutePattern: string): RegExp {
  const escaped = absolutePattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*\//g, "__GLOBSTAR_SLASH__")
    .replace(/\*\*/g, "__GLOBSTAR__")
    .replace(/\*/g, "[^/]*")
    .replace(/\?/g, "[^/]")
    .replaceAll("__GLOBSTAR_SLASH__", "(?:.*/)?")
    .replaceAll("__GLOBSTAR__", ".*");
  return new RegExp(`^${escaped}$`);
}

export function matchesPattern(filePath: string, patterns: string[], cwd = process.cwd()): boolean {
  const absolutePath = canonicalizePath(filePath, cwd);
  return resolvePolicyPatterns(patterns, cwd).some((absolutePattern) => {
    if (absolutePattern.endsWith("/**")) {
      const root = absolutePattern.slice(0, -3) || "/";
      return absolutePath === root || absolutePath.startsWith(root === "/" ? "/" : root + "/");
    }
    if (containsGlob(absolutePattern)) return globRegex(absolutePattern).test(absolutePath);
    const separator = absolutePattern.endsWith("/") ? "" : "/";
    return absolutePath === absolutePattern || absolutePath.startsWith(absolutePattern + separator);
  });
}

function lexicalPathIsWithin(path: string, ancestor: string): boolean {
  const candidate = resolveLexicalPath(path);
  const root = resolveLexicalPath(ancestor);
  return candidate === root || candidate.startsWith(root + "/");
}

export function pathIsWithin(path: string, ancestor: string): boolean {
  const candidate = canonicalizePath(path);
  const root = canonicalizePath(ancestor);
  return candidate === root || candidate.startsWith(root + "/");
}

export function evaluateReadPolicy(input: ReadPolicyInput): PathDecision {
  const lexicalPath = resolveLexicalPath(input.path, input.cwd);
  const path = canonicalizePath(lexicalPath, input.cwd);
  if (matchesPattern(path, input.denyRead, input.cwd)) return "hard-deny";
  if (input.modeBehavior === "deny") return "mode-deny";
  if (matchesPattern(path, input.allowRead, input.cwd)) return "allow";

  if (input.readScope === "open") return "outside-scope-allow";
  if (
    input.readScope === "home" &&
    !lexicalPathIsWithin(lexicalPath, homedir()) &&
    !pathIsWithin(path, homedir())
  ) {
    return "outside-scope-allow";
  }
  return "prompt";
}

/** Return hard-deny patterns at or below a recursive operation root. */
export function hardDeniesWithin(rootPath: string, denyRead: string[], cwd: string): string[] {
  const root = canonicalizePath(rootPath, cwd);
  return resolvePolicyPatterns(denyRead, cwd).filter((pattern) => {
    const staticPrefix = staticGlobPrefix(pattern).replace(/\/$/, "");
    return staticPrefix === root || staticPrefix.startsWith(root + "/");
  });
}
