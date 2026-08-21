export type OtherwiseAction = "prompt" | "deny";

export interface OtherwisePolicy {
  read: OtherwiseAction;
  write: OtherwiseAction;
  network: OtherwiseAction;
}

export interface CategoricalDenies {
  read: boolean;
  write: boolean;
  network: boolean;
}

export const DEFAULT_MODE = "default";
export const DEFAULT_OTHERWISE_POLICY: OtherwisePolicy = {
  read: "prompt",
  write: "prompt",
  network: "prompt",
};
export const NO_CATEGORICAL_DENIES: CategoricalDenies = {
  read: false,
  write: false,
  network: false,
};

const LEGACY_MODE_POLICIES: Readonly<Record<string, OtherwisePolicy>> = {
  default: DEFAULT_OTHERWISE_POLICY,
  "read-only": {
    read: "prompt",
    write: "deny",
    network: "prompt",
  },
  build: DEFAULT_OTHERWISE_POLICY,
};

export function validateModeName(mode: string): string {
  if (!/^[a-z0-9][a-z0-9_-]*$/.test(mode)) {
    throw new Error(
      `Invalid sandbox mode "${mode}"; use lowercase letters, digits, hyphens, or underscores`,
    );
  }
  return mode;
}

export function parseOtherwiseAction(value: unknown, field: string): OtherwiseAction {
  if (value !== "prompt" && value !== "deny") {
    throw new Error(`${field} must be prompt or deny`);
  }
  return value;
}

export function getLegacyModePolicy(mode: string): OtherwisePolicy | undefined {
  return LEGACY_MODE_POLICIES[mode];
}

export function getLegacyCategoricalDenies(mode: string): CategoricalDenies {
  const policy = getLegacyModePolicy(mode);
  return {
    read: policy?.read === "deny",
    write: policy?.write === "deny",
    network: policy?.network === "deny",
  };
}
