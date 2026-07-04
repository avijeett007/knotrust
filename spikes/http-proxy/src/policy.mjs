// SPIKE — a two-entry tool->tier map. Just enough to make one tool
// "critical" (triggers the InputRequiredResult/requestState path) and one
// "routine" (plain passthrough), so the demo has something to branch on.
// The real product's tier resolution (annotation-seeded + pack + user
// config precedence, P0-E4/E7) is out of scope here on purpose.

/** @type {Record<string, "critical" | "routine">} */
export const TIERS = {
  "stripe.refund_payment": "critical",
  "stripe.list_charges": "routine",
};

export function tierFor(toolName) {
  return TIERS[toolName] ?? "routine";
}
