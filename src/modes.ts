export type RestrictionBehavior = "prompt" | "deny";

export interface ModePolicy {
  read: RestrictionBehavior;
  write: RestrictionBehavior;
  network: RestrictionBehavior;
}

export const DEFAULT_MODE = "default";

export const MODE_POLICIES: Record<string, ModePolicy> = {
  default: {
    read: "prompt",
    write: "prompt",
    network: "prompt",
  },
  "read-only": {
    read: "prompt",
    write: "deny",
    network: "prompt",
  },
  build: {
    read: "prompt",
    write: "prompt",
    network: "prompt",
  },
};

export function getModePolicy(mode: string): ModePolicy {
  return MODE_POLICIES[mode] ?? MODE_POLICIES.default;
}
