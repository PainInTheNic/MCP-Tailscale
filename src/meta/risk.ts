/** Risk-level gating. read < write < admin. */
import type { RiskLevel } from "../config.js";

const RANK: Record<RiskLevel, number> = { read: 0, write: 1, admin: 2 };

/** True if a tool requiring `required` may run at the configured `current` level. */
export function allows(current: RiskLevel, required: RiskLevel): boolean {
  return RANK[current] >= RANK[required];
}
