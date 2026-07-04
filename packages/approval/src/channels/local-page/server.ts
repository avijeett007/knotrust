/**
 * @knotrust/approval — the localhost approval page server (P0-E6-T3;
 * rulings R96–R100).
 *
 * A tiny `node:http` server — NO framework (Hono is Phase 2, for the HTTP
 * proxy, not this page) — bound to `127.0.0.1` ONLY, on an ephemeral port
 * (`listen(0)`), that lets a human Approve-once / Always-allow / Deny a
 * pending approval the block-and-wait channel (E6-T2) is holding. This is
 * also the future URL-mode elicitation target (R96).
 *
 * ## Human authentication & hardening — the acceptance IS this list (R98)
 *
 * - **Loopback bind**: `server.listen(0, "127.0.0.1")` — never `0.0.0.0`.
 * - **`Host` validation (DNS-rebinding defense)**: EVERY request — before any
 *   routing — must carry `Host: 127.0.0.1:<port>` or `Host: localhost:<port>`
 *   exactly; anything else (a browser DNS-rebound to resolve some external
 *   name to `127.0.0.1` would still send that external name as `Host`) is
 *   403, audited `bad_host`. This is what actually defeats rebinding: the
 *   loopback bind alone only proves nothing OFF this machine can connect; a
 *   page open in the human's own browser, rebound via DNS trickery, connects
 *   FROM localhost but presents an attacker's `Host` — this check is the one
 *   that catches that.
 * - **`Origin` validation**: every state-changing POST (to `/approve/action`
 *   only — the page's own GET render never mutates) must carry
 *   `Origin: http://127.0.0.1:<port>` or `http://localhost:<port>` exactly.
 *   POLICY DECISION (documented per the task spec's instruction to "decide
 *   and document the exact policy"): a MISSING `Origin` is REJECTED, not
 *   treated as same-origin — the acceptance bar is explicit ("wrong/missing
 *   Origin ... rejected"), and a same-origin browser POST from this page's
 *   own rendered form always DOES send `Origin` (it is a cross-site POST
 *   from the browser's perspective — different form action origin
 *   possibility aside, browsers attach `Origin` to same-origin POSTs too),
 *   so requiring it costs nothing for the legitimate flow.
 * - **CSRF**: a per-render nonce (`csrfToken`), generated fresh on every GET
 *   render and tracked server-side per approval id, distinct from the URL
 *   token. `/approve/action` requires it in the POST body; missing/wrong is
 *   403, audited `bad_csrf`.
 * - **POST-only mutations**: `/approve/action` is POST-only — GET there is
 *   405 and touches NOTHING (no orchestrator call, no grant mint). The
 *   page's own render endpoint, `/approve`, is GET-only (a POST there is
 *   405 too, for hygiene, though not itself part of the acceptance battery).
 * - **No cookies / no session**: this server never sets a `Set-Cookie`
 *   header anywhere. State is the URL token + the per-render CSRF nonce,
 *   held in this module's own in-memory map — never a session.
 * - **Single-use URL token**: bound to ONE approval id (R97), invalidated
 *   the instant a terminal action is ACCEPTED (synchronously, before the
 *   mint/resolve `await`s below — the same "claim before the first await"
 *   discipline `lifecycle.ts`'s own `resolving` latch uses, so a
 *   double-submit race can't process twice). Replaying the URL (GET) or the
 *   form POST afterward is 410 Gone, audited `replayed_token`.
 * - **Every rejection is audited** as `approval_channel_violation`
 *   (`@knotrust/store`'s `AuditEventType`, added by this task) — the reason
 *   only, NEVER the token value (see `auditViolation` below).
 *
 * ## Two distinct paths, not one ("the approve/deny endpoint" is POST-only)
 *
 * `GET /approve?id=&token=` renders the form (view-only, side-effect-free
 * w.r.t. approval state). `POST /approve/action` is the ONLY endpoint that
 * ever calls `orchestrator.resolve()` or mints a grant — this is "the
 * approve/deny endpoint" the acceptance bar means by "a GET to the
 * approve/deny endpoint mutates nothing (405)": hitting it with GET performs
 * no mutation and answers 405, while the page's own render endpoint
 * legitimately answers GET with 200.
 *
 * ## "Always allow" — durable grant BEFORE resolve (R99)
 *
 * On `action=always_allow`, this handler mints a DURABLE grant (via the
 * injected `mintDurableGrant` — production wiring partially applies
 * `@knotrust/grants`' real `mintDurableGrant` over the real store/keyStore,
 * exactly mirroring how `lifecycle.ts`'s `MintEphemeralGrantFn` is wired)
 * scoped to the approved call's exact tool + resource (never widened to a
 * wildcard — the tightest scope that still satisfies "next identical call
 * allows," least blind-escalation risk), THEN calls
 * `orchestrator.resolve(id, "approved", ...)` — so the CURRENT call passes
 * (via the ephemeral grant `resolve()` itself mints, or the fresh durable
 * one — either way `decide()`'s re-evaluation sees an allow) AND future
 * identical calls allow without approval, because the durable grant is
 * non-single-use and persists past this approval. The scope + a default
 * 30-day expiry are shown to the human on the GET render, BEFORE they can
 * click confirm (PRD §7 no-blind-escalation at the UX level) — see
 * `describeDurableGrantPreview` below.
 *
 * ## No re-fetch of server-controlled data (R96)
 *
 * This module renders exclusively from the frozen `ApprovalRequest` the
 * injected `getApprovalRequest(id)` returns (see `registry.ts`) — itself
 * sourced from the SAME frozen `DecisionRequest` snapshot `lifecycle.ts`
 * captured at `request()` time. It never asks the fronted MCP server for
 * anything.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { MintDurableGrantInput, MintResult } from "@knotrust/grants";
import { type AuditSink, computeArgsHash } from "@knotrust/store";
import type { ApprovalOrchestrator, ApprovalRequest } from "../../lifecycle.js";
import {
  type ApprovalPageAction,
  renderApprovalPage,
  renderDonePage,
  renderMessagePage,
} from "./html.js";

// ---------------------------------------------------------------------------
// Deps
// ---------------------------------------------------------------------------

export interface ApprovalPageServerDeps {
  /** The E6-T1 lifecycle orchestrator — `status()`/`resolve()` drive the actual approval. Typically the WRAPPED orchestrator from `withApprovalRequestRegistry` (`registry.ts`). */
  orchestrator: ApprovalOrchestrator;
  /** Returns the full `ApprovalRequest` (frozen snapshot) for rendering, given an approval id. `undefined` ⇒ unknown to this server. See `registry.ts`. */
  getApprovalRequest(id: string): ApprovalRequest | undefined;
  /**
   * Mints a DURABLE grant for "Always allow" — the same `LifecycleMintDeps`-
   * partial-application shape `lifecycle.ts`'s `MintEphemeralGrantFn` uses,
   * so this module carries no runtime dependency on a concrete `KeyStore`/
   * `GrantStore` (only the `@knotrust/grants` TYPES `MintDurableGrantInput`/
   * `MintResult`). Production wiring (`packages/cli`'s `enforcement.ts`)
   * partially applies `@knotrust/grants`' real `mintDurableGrant`.
   */
  mintDurableGrant(input: MintDurableGrantInput): Promise<MintResult>;
  audit: AuditSink;
  nowEpochSeconds(): number;
  /** "Always allow" durable-grant default lifetime. Default 30 days (R99). */
  defaultDurableGrantTtlSeconds?: number;
  /** Injected CSRF-nonce generator (tests only) — defaults to `randomBytes(18).toString("base64url")`. */
  generateCsrfToken?(): string;
}

export interface ApprovalPageServer {
  /** Builds the tokened GET URL a human opens, and registers `token` as the current valid (unused) token for `approvalId`. Throws if called before `start()` resolves (the port is not yet known). */
  url(approvalId: string, token: string): string;
  /** Binds `127.0.0.1:<ephemeral port>` and starts listening. */
  start(): Promise<void>;
  /** Closes the server. */
  stop(): Promise<void>;
  /** The bound port — `0` before `start()` resolves. */
  readonly port: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_DURABLE_GRANT_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days (R99)
const MAX_BODY_BYTES = 8192;
const APPROVE_ACTIONS: ReadonlySet<string> = new Set([
  "approve",
  "always_allow",
  "deny",
]);

type ViolationReason =
  | "bad_host"
  | "bad_origin"
  | "bad_csrf"
  | "bad_token"
  | "replayed_token"
  | "wrong_method";

// ---------------------------------------------------------------------------
// Internal per-approval token/CSRF state.
// ---------------------------------------------------------------------------

interface PendingEntry {
  token: string;
  used: boolean;
  csrfToken?: string;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Constant-time equality for secret comparisons (the URL token, the CSRF
 * nonce) — plain `!==` on a `string` short-circuits at the first differing
 * byte, a real (if narrow, over a loopback socket) timing side channel for a
 * value whose whole security property is "an attacker can't guess it."
 * `node:crypto`'s `timingSafeEqual` requires equal-length buffers and throws
 * otherwise, so a length mismatch is handled by still doing a same-cost
 * dummy comparison (against `b` itself) before returning `false` — the
 * length itself is not a secret worth defending (both values are
 * fixed-format, high-entropy strings), only the CONTENT is.
 */
function timingSafeEqualString(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    timingSafeEqual(bufB, bufB);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

// ---------------------------------------------------------------------------
// createApprovalPageServer
// ---------------------------------------------------------------------------

export function createApprovalPageServer(
  deps: ApprovalPageServerDeps,
): ApprovalPageServer {
  const pending = new Map<string, PendingEntry>();
  const defaultTtlSeconds =
    deps.defaultDurableGrantTtlSeconds ?? DEFAULT_DURABLE_GRANT_TTL_SECONDS;
  const generateCsrfToken =
    deps.generateCsrfToken ??
    (() => `csrf_${randomBytes(18).toString("base64url")}`);

  let port = 0;
  let listening = false;

  // -------------------------------------------------------------------------
  // Audit — every rejection, NEVER the token value (R98).
  // -------------------------------------------------------------------------

  function auditViolation(
    reason: ViolationReason,
    id: string | undefined,
  ): void {
    const req = id !== undefined ? deps.getApprovalRequest(id) : undefined;
    try {
      deps.audit.append({
        type: "approval_channel_violation",
        surface: "local_page",
        subject: req?.subject.id ?? "unknown",
        agent: req?.agent.id ?? "unknown",
        tool: req?.decisionRequest.action.name ?? "unknown",
        argsHash: computeArgsHash(
          req?.decisionRequest.context.arguments ?? null,
        ),
        reason,
        ...(id !== undefined ? { approvalId: id } : {}),
      });
    } catch (err) {
      // Best-effort (matches this channel's own pending-record/heartbeat
      // posture, block-and-wait.ts): the HTTP rejection itself is the real
      // control and already stands regardless of whether this forensic line
      // could be written. Never let an audit-sink failure become a crash or
      // a hung response.
      process.stderr.write(
        `knotrust: approval-page audit append failed for reason "${reason}"` +
          `${id !== undefined ? ` (id=${id})` : ""}: ${errorMessage(err)}\n`,
      );
    }
  }

  // -------------------------------------------------------------------------
  // Host / Origin validation (R98).
  // -------------------------------------------------------------------------

  function isValidHost(hostHeader: string | undefined): boolean {
    if (hostHeader === undefined) return false;
    return (
      hostHeader === `127.0.0.1:${port}` || hostHeader === `localhost:${port}`
    );
  }

  function isValidOrigin(originHeader: string | undefined): boolean {
    if (originHeader === undefined) return false; // policy: missing is rejected (see module header)
    return (
      originHeader === `http://127.0.0.1:${port}` ||
      originHeader === `http://localhost:${port}`
    );
  }

  // -------------------------------------------------------------------------
  // Response helpers.
  // -------------------------------------------------------------------------

  function sendHtml(res: ServerResponse, status: number, html: string): void {
    res.writeHead(status, {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": Buffer.byteLength(html, "utf8"),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      // No inline/external script ever runs on this page (zero client-side
      // JS by design) — `default-src 'none'` is defense-in-depth on top of
      // the escaping in html.ts, not a substitute for it.
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    });
    res.end(html);
  }

  // -------------------------------------------------------------------------
  // Durable-grant scope derivation (R99) — exact tool + exact resource, the
  // tightest scope that still satisfies "next identical call allows."
  // -------------------------------------------------------------------------

  function buildDurableGrantInput(
    request: ApprovalRequest,
    ttlSeconds: number,
  ): MintDurableGrantInput {
    return {
      principal: { type: request.subject.type, id: request.subject.id },
      agent: { id: request.agent.id, type: request.agent.type },
      tool: request.decisionRequest.action.name,
      scope: {
        resourceType: request.decisionRequest.resource.type,
        idPattern: request.decisionRequest.resource.id,
      },
      tier: request.tier,
      envelopeScope: "personal",
      ttlSeconds,
    };
  }

  function describeDurableGrantPreview(
    request: ApprovalRequest,
    ttlSeconds: number,
  ): string {
    const days = Math.round(ttlSeconds / 86_400);
    const unit = days === 1 ? "day" : "days";
    return (
      `${request.decisionRequest.action.name} on ` +
      `${request.decisionRequest.resource.type}:${request.decisionRequest.resource.id} ` +
      `— expires in ${days} ${unit}`
    );
  }

  // -------------------------------------------------------------------------
  // Body parsing — application/x-www-form-urlencoded, size-capped.
  // -------------------------------------------------------------------------

  function readFormBody(req: IncomingMessage): Promise<URLSearchParams> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          reject(new Error("request body too large"));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => {
        resolve(new URLSearchParams(Buffer.concat(chunks).toString("utf8")));
      });
      req.on("error", reject);
    });
  }

  // -------------------------------------------------------------------------
  // GET /approve — render (view-only, no mutation).
  // -------------------------------------------------------------------------

  async function handleRenderApprove(
    res: ServerResponse,
    searchParams: URLSearchParams,
  ): Promise<void> {
    const id = searchParams.get("id");
    const token = searchParams.get("token");
    if (id === null || token === null || id === "" || token === "") {
      sendHtml(
        res,
        400,
        renderMessagePage("Bad request", "Missing id or token."),
      );
      return;
    }

    const entry = pending.get(id);
    if (entry === undefined || !timingSafeEqualString(entry.token, token)) {
      // Unknown id or a wrong token for a known id are folded into the SAME
      // fail-closed response — never confirm/deny id existence to a guesser.
      auditViolation("bad_token", id);
      sendHtml(
        res,
        404,
        renderMessagePage("Not found", "This approval link is invalid."),
      );
      return;
    }

    if (entry.used) {
      auditViolation("replayed_token", id);
      sendHtml(
        res,
        410,
        renderMessagePage("Gone", "This approval has already been resolved."),
      );
      return;
    }

    const approvalRequest = deps.getApprovalRequest(id);
    if (approvalRequest === undefined) {
      sendHtml(
        res,
        500,
        renderMessagePage("Unavailable", "Approval details are unavailable."),
      );
      return;
    }

    // Catch a race: the underlying approval may have already gone terminal
    // via a different channel (e.g. `knotrust approvals`, or the lifecycle
    // orchestrator's own lazy expiry) between mint and this GET.
    const handle = await deps.orchestrator.status(id);
    if (handle.state !== "pending" && handle.state !== "requested") {
      entry.used = true;
      sendHtml(
        res,
        410,
        renderMessagePage("Gone", `This approval is already ${handle.state}.`),
      );
      return;
    }

    const csrfToken = generateCsrfToken();
    entry.csrfToken = csrfToken;
    const grantPreview = describeDurableGrantPreview(
      approvalRequest,
      defaultTtlSeconds,
    );

    sendHtml(
      res,
      200,
      renderApprovalPage({
        approvalId: id,
        token,
        csrfToken,
        tool: approvalRequest.decisionRequest.action.name,
        server: approvalRequest.decisionRequest.surface.server,
        tier: approvalRequest.tier,
        args: approvalRequest.decisionRequest.context.arguments,
        grantPreview,
      }),
    );
  }

  // -------------------------------------------------------------------------
  // POST /approve/action — the ONLY mutating endpoint.
  // -------------------------------------------------------------------------

  async function handleAction(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    let body: URLSearchParams;
    try {
      body = await readFormBody(req);
    } catch {
      sendHtml(
        res,
        400,
        renderMessagePage("Bad request", "Malformed request body."),
      );
      return;
    }

    const id = body.get("id") ?? undefined;

    if (!isValidOrigin(req.headers.origin)) {
      auditViolation("bad_origin", id);
      sendHtml(
        res,
        403,
        renderMessagePage("Forbidden", "Origin not recognized."),
      );
      return;
    }

    const token = body.get("token");
    if (id === undefined || token === null || id === "") {
      sendHtml(
        res,
        400,
        renderMessagePage("Bad request", "Missing id or token."),
      );
      return;
    }

    const entry = pending.get(id);
    if (entry === undefined || !timingSafeEqualString(entry.token, token)) {
      auditViolation("bad_token", id);
      sendHtml(
        res,
        404,
        renderMessagePage("Not found", "This approval link is invalid."),
      );
      return;
    }

    if (entry.used) {
      auditViolation("replayed_token", id);
      sendHtml(
        res,
        410,
        renderMessagePage("Gone", "This approval has already been resolved."),
      );
      return;
    }

    const csrf = body.get("csrf");
    if (
      csrf === null ||
      entry.csrfToken === undefined ||
      !timingSafeEqualString(csrf, entry.csrfToken)
    ) {
      auditViolation("bad_csrf", id);
      sendHtml(
        res,
        403,
        renderMessagePage("Forbidden", "CSRF token missing or invalid."),
      );
      return;
    }

    const action = body.get("action");
    if (action === null || !APPROVE_ACTIONS.has(action)) {
      sendHtml(res, 400, renderMessagePage("Bad request", "Unknown action."));
      return;
    }
    const approvalAction = action as ApprovalPageAction;

    // Claim the token BEFORE any async work — mirrors lifecycle.ts's own
    // synchronous "resolving" latch: a concurrent double-submit for the same
    // id must see `used === true` and be rejected, not race the mint/resolve
    // below.
    entry.used = true;

    const approvalRequest = deps.getApprovalRequest(id);
    try {
      if (approvalAction === "always_allow") {
        if (approvalRequest === undefined) {
          throw new Error("approval request unavailable for always_allow mint");
        }
        const grantInput = buildDurableGrantInput(
          approvalRequest,
          defaultTtlSeconds,
        );
        await deps.mintDurableGrant(grantInput);
      }
      const outcome = approvalAction === "deny" ? "denied" : "approved";
      await deps.orchestrator.resolve(id, outcome, "elicitation_url");
      sendHtml(res, 200, renderDonePage(approvalAction));
    } catch (err) {
      process.stderr.write(
        `knotrust: approval-page action "${approvalAction}" failed for ${id}: ${errorMessage(err)}\n`,
      );
      sendHtml(
        res,
        500,
        renderMessagePage(
          "Error",
          "Could not complete this action. Check the terminal for details.",
        ),
      );
    }
  }

  // -------------------------------------------------------------------------
  // Top-level request routing.
  // -------------------------------------------------------------------------

  async function route(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const method = req.method ?? "GET";
    const parsedUrl = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);

    // Host validation FIRST — applies to every request, every path (R98:
    // the DNS-rebinding defense). Deliberately does not attempt to resolve
    // `id` from the query string here for GETs so an id can still be
    // audited against on the render path below; for a POST, `id` isn't
    // known until the body is read, so this early check simply omits it.
    if (!isValidHost(req.headers.host)) {
      const idHint = parsedUrl.searchParams.get("id") ?? undefined;
      auditViolation("bad_host", idHint);
      sendHtml(
        res,
        403,
        renderMessagePage(
          "Forbidden",
          "This request's Host header is not recognized.",
        ),
      );
      return;
    }

    if (parsedUrl.pathname === "/approve") {
      if (method !== "GET") {
        auditViolation(
          "wrong_method",
          parsedUrl.searchParams.get("id") ?? undefined,
        );
        res.setHeader("Allow", "GET");
        sendHtml(res, 405, renderMessagePage("Method not allowed", "Use GET."));
        return;
      }
      await handleRenderApprove(res, parsedUrl.searchParams);
      return;
    }

    if (parsedUrl.pathname === "/approve/action") {
      if (method !== "POST") {
        auditViolation(
          "wrong_method",
          parsedUrl.searchParams.get("id") ?? undefined,
        );
        res.setHeader("Allow", "POST");
        sendHtml(
          res,
          405,
          renderMessagePage("Method not allowed", "Use POST."),
        );
        return;
      }
      await handleAction(req, res);
      return;
    }

    sendHtml(res, 404, renderMessagePage("Not found", "Unknown page."));
  }

  const server: Server = createServer((req, res) => {
    void route(req, res).catch((err: unknown) => {
      process.stderr.write(
        `knotrust: approval-page request handler threw: ${errorMessage(err)}\n`,
      );
      if (!res.headersSent) {
        sendHtml(res, 500, renderMessagePage("Error", "Internal error."));
      } else {
        res.end();
      }
    });
  });

  return {
    url(approvalId: string, token: string): string {
      if (!listening) {
        throw new Error(
          "createApprovalPageServer: url() called before start() resolved",
        );
      }
      pending.set(approvalId, { token, used: false });
      return `http://127.0.0.1:${port}/approve?id=${encodeURIComponent(approvalId)}&token=${encodeURIComponent(token)}`;
    },
    start(): Promise<void> {
      return new Promise((resolve, reject) => {
        function onError(err: Error): void {
          server.removeListener("error", onError);
          reject(err);
        }
        server.once("error", onError);
        // Loopback bind ONLY (R98) — never "0.0.0.0", never omitted (which
        // would default to all interfaces).
        server.listen(0, "127.0.0.1", () => {
          server.removeListener("error", onError);
          const addr = server.address();
          if (addr === null || typeof addr === "string") {
            reject(
              new Error(
                "createApprovalPageServer: unexpected server.address() shape after listen",
              ),
            );
            return;
          }
          port = addr.port;
          listening = true;
          resolve();
        });
      });
    },
    stop(): Promise<void> {
      return new Promise((resolve, reject) => {
        server.close((err) => {
          if (err) {
            reject(err);
            return;
          }
          listening = false;
          resolve();
        });
      });
    },
    get port(): number {
      return port;
    },
  };
}
