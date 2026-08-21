export type RestrictionBehavior = "prompt" | "deny";

export interface ModePolicy {
  read: RestrictionBehavior;
  write: RestrictionBehavior;
  network: RestrictionBehavior;
}

export const DEFAULT_MODE = "default";
export const DEFAULT_MODE_POLICY: ModePolicy = {
  read: "prompt",
  write: "prompt",
  network: "prompt",
};

const LEGACY_MODE_POLICIES: Readonly<Record<string, ModePolicy>> = {
  default: DEFAULT_MODE_POLICY,
  "read-only": {
    read: "prompt",
    write: "deny",
    network: "prompt",
  },
  build: DEFAULT_MODE_POLICY,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validateModeName(mode: string): string {
  if (!/^[a-z0-9][a-z0-9_-]*$/.test(mode)) {
    throw new Error(
      `Invalid sandbox mode "${mode}"; use lowercase letters, digits, hyphens, or underscores`,
    );
  }
  return mode;
}

export function parseModePolicy(value: unknown, source: string): ModePolicy {
  if (!isRecord(value)) throw new Error(`${source}: mode must be an object`);
  const supportedFields = new Set(["read", "write", "network"]);
  const unsupported = Object.keys(value).find((field) => !supportedFields.has(field));
  if (unsupported) throw new Error(`${source}: unsupported mode field ${unsupported}`);
  const parsed: Partial<ModePolicy> = {};
  for (const field of ["read", "write", "network"] as const) {
    const behavior = value[field];
    if (behavior !== "prompt" && behavior !== "deny") {
      throw new Error(`${source}: mode.${field} must be prompt or deny`);
    }
    parsed[field] = behavior;
  }
  if (parsed.read === "deny" && parsed.write !== "deny") {
    throw new Error(`${source}: mode read deny requires write deny because writes imply reads`);
  }
  return parsed as ModePolicy;
}

export function getLegacyModePolicy(mode: string): ModePolicy | undefined {
  return LEGACY_MODE_POLICIES[mode];
}
