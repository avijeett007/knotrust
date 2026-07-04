/**
 * @knotrust/approval — localhost approval page: embedded HTML/CSS templates
 * (P0-E6-T3; ruling R99).
 *
 * Every asset this page ever serves is a STRING LITERAL in this module —
 * never a `readFileSync` of an adjacent `.html`/`.css` file. That is what
 * lets the page survive tsup bundling into the published `knotrust` CLI
 * (ADR-0016, R100): there is no separate asset file for the bundler to lose
 * track of or for the published tarball to omit, so `dist/bin.js` alone is
 * self-contained. There is also ZERO client-side JavaScript — every action
 * is a plain HTML `<form method="POST">`, matching the task spec's "zero
 * build tooling" requirement and shrinking the page's own attack surface (no
 * script to inject INTO even if the escaping below had a bug — see the
 * `Content-Security-Policy` header `server.ts` sends alongside this HTML,
 * `default-src 'none'`).
 *
 * ## XSS-proofing (R99) — escape everything that did not originate as a
 * literal string in THIS module
 *
 * `escapeHtml` is the ONLY thing standing between a hostile tool/server name
 * or a `<script>`-laden argument value and a live tag in the rendered page.
 * Every dynamic value threaded into the templates below — tool name, server
 * name, tier, argument keys/values, the grant-scope preview, even the
 * approval id/token/CSRF nonce this module itself generates — is passed
 * through `escapeHtml` before concatenation. This is deliberately
 * belt-and-braces: the id/token/CSRF values are ALWAYS `[A-Za-z0-9_-]`
 * (never need escaping) but escaping them anyway means a future change to
 * their generator can never silently reopen an injection point here.
 */

// ---------------------------------------------------------------------------
// escapeHtml — the one XSS defense this module has, and the only one it needs.
// ---------------------------------------------------------------------------

/**
 * Escapes the five characters that matter for safely embedding untrusted
 * text inside HTML element content OR a double-quoted attribute value:
 * `&` (must go first — every other replacement below introduces literal
 * `&`, which must not itself be re-escaped), `<`, `>` (close a tag/open a
 * new one), `"` (breaks out of a double-quoted attribute), and `'` (breaks
 * out of a single-quoted attribute — this module only ever uses double
 * quotes for attributes, but escaping `'` too is free defense-in-depth).
 */
export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// Argument-summary rendering — from OUR parse of context.arguments, never
// server-supplied HTML (R99).
// ---------------------------------------------------------------------------

/** Renders one argument value as human-readable text (pre-escaping). */
function summarizeArgValue(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function renderArgumentSummary(
  args: Record<string, unknown> | undefined,
): string {
  const entries = args !== undefined ? Object.entries(args) : [];
  if (entries.length === 0) {
    return '<p class="kt-empty">(no arguments)</p>';
  }
  const rows = entries
    .map(([key, value]) => {
      const rendered = escapeHtml(summarizeArgValue(value));
      return `<tr><th>${escapeHtml(key)}</th><td><code>${rendered}</code></td></tr>`;
    })
    .join("\n");
  return `<table class="kt-args">\n${rows}\n</table>`;
}

// ---------------------------------------------------------------------------
// Shared layout
// ---------------------------------------------------------------------------

const STYLE = `
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1.5rem; color: #1a1a1a; background: #fafafa; }
  h1 { font-size: 1.25rem; }
  table.kt-args { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  table.kt-args th, table.kt-args td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid #ddd; vertical-align: top; }
  table.kt-args th { width: 30%; font-weight: 600; color: #444; }
  code { word-break: break-all; }
  .kt-actions { display: flex; gap: 0.75rem; margin-top: 1rem; flex-wrap: wrap; }
  button { font-size: 1rem; padding: 0.6rem 1rem; border-radius: 6px; border: 1px solid #ccc; cursor: pointer; background: #fff; }
  button.kt-approve { background: #16a34a; color: #fff; border-color: #16a34a; }
  button.kt-always { background: #2563eb; color: #fff; border-color: #2563eb; }
  button.kt-deny { background: #dc2626; color: #fff; border-color: #dc2626; }
  .kt-meta { color: #444; font-size: 0.95rem; }
  .kt-preview { background: #eef2ff; border: 1px solid #c7d2fe; border-radius: 6px; padding: 0.6rem 0.8rem; font-size: 0.85rem; margin-top: 1.25rem; }
`;

function baseLayout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
${body}
</body>
</html>
`;
}

// ---------------------------------------------------------------------------
// The approval form (GET render).
// ---------------------------------------------------------------------------

export interface ApprovalPageView {
  approvalId: string;
  token: string;
  csrfToken: string;
  tool: string;
  server: string | undefined;
  tier: "sensitive" | "critical";
  args: Record<string, unknown> | undefined;
  /** Human-readable summary of the durable grant "Always allow" would create — computed BEFORE mint, shown before confirm (PRD §7 no-blind-escalation). */
  grantPreview: string;
}

export function renderApprovalPage(view: ApprovalPageView): string {
  const serverLine =
    view.server !== undefined ? ` on server "${escapeHtml(view.server)}"` : "";
  const body = `
<h1>knotrust: approval requested</h1>
<p class="kt-meta">Tool <code>${escapeHtml(view.tool)}</code>${serverLine} — <strong>${escapeHtml(view.tier)}</strong> tier.</p>
${renderArgumentSummary(view.args)}
<form method="POST" action="/approve/action">
  <input type="hidden" name="id" value="${escapeHtml(view.approvalId)}">
  <input type="hidden" name="token" value="${escapeHtml(view.token)}">
  <input type="hidden" name="csrf" value="${escapeHtml(view.csrfToken)}">
  <div class="kt-actions">
    <button class="kt-approve" type="submit" name="action" value="approve">Approve once</button>
    <button class="kt-deny" type="submit" name="action" value="deny">Deny</button>
  </div>
  <div class="kt-preview">
    <strong>Always allow</strong> creates a standing grant: ${escapeHtml(view.grantPreview)}.
    <div class="kt-actions">
      <button class="kt-always" type="submit" name="action" value="always_allow">Always allow (create grant)</button>
    </div>
  </div>
</form>
`;
  return baseLayout("knotrust approval", body);
}

// ---------------------------------------------------------------------------
// Terminal / informational pages.
// ---------------------------------------------------------------------------

export type ApprovalPageAction = "approve" | "always_allow" | "deny";

export function renderDonePage(action: ApprovalPageAction): string {
  const heading = action === "deny" ? "denied" : "approved";
  const message =
    action === "deny"
      ? "Denied. The call will not proceed."
      : action === "always_allow"
        ? "Approved — and a standing grant was created so future identical calls no longer need approval."
        : "Approved. The call may now proceed.";
  return baseLayout(
    "knotrust approval — done",
    `<h1>knotrust: ${escapeHtml(heading)}</h1><p>${escapeHtml(message)}</p>`,
  );
}

export function renderMessagePage(title: string, message: string): string {
  return baseLayout(
    `knotrust — ${title}`,
    `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`,
  );
}
