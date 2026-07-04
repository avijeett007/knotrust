// SPIKE — the actual thing under test: a minimal Hono reverse-proxy
// "replica" implementing the two routes SEP-2322 (MRTR) needs for a
// stateless pending-approval flow:
//
//   POST /mcp         — normal tools/call entry. On a critical tool, mints
//                        an InputRequiredResult-shaped response carrying
//                        requestState instead of holding the call open.
//   POST /mcp/resume  — the client's "fresh, independent request" carrying
//                        inputResponses + the echoed requestState. Verifies
//                        + decrypts requestState and, if approved, forwards
//                        to the upstream — all WITHOUT this process ever
//                        having seen the original /mcp call (that's the
//                        point: two separate replica PROCESSES run this
//                        same module, and either one can serve either
//                        route).
//
// Mcp-Method/Mcp-Name headers (SEP-2243) are read and logged for
// routing/telemetry ONLY (brief §C2) — the tier/policy decision below is
// computed exclusively from the parsed JSON-RPC BODY. A header/body
// mismatch is rejected before any decision logic runs, mirroring the RC's
// mandated HeaderMismatch behavior.
//
// This file is imported directly by run-demo.mjs for the in-process
// timing/measurement helper, and executed as its own OS process (via
// `node src/replica.mjs`, see the bottom of the file) for the two actual
// replica instances the demo drives over real HTTP.

import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { tierFor } from "./policy.mjs";
import {
  loadSharedKey,
  mintRequestState,
  RequestStateError,
  verifyAndDecrypt,
} from "./request-state.mjs";

/**
 * @param {{ name: string, key: Buffer, upstreamUrl: string }} opts
 */
export function createReplicaApp({ name, key, upstreamUrl }) {
  const app = new Hono();

  app.post("/mcp", async (c) => {
    const body = await c.req.json();
    const headerMethod = c.req.header("mcp-method");
    const headerName = c.req.header("mcp-name");
    const principal = c.req.header("x-principal") ?? "unknown";

    // SEP-2243: headers mirror the body for fast-path routing/telemetry —
    // never trusted for the decision, and a mismatch is rejected outright.
    const bodyMethod = body.method;
    const bodyName = body.params?.name;
    if (headerMethod && headerMethod !== bodyMethod) {
      console.error(
        `[replica ${name}] REJECT header/body mismatch: Mcp-Method=${headerMethod} body.method=${bodyMethod}`,
      );
      return c.json(
        {
          jsonrpc: "2.0",
          id: body.id ?? null,
          error: { code: -32001, message: "HeaderMismatch: Mcp-Method does not match body.method" },
        },
        400,
      );
    }
    if (headerName && bodyName && headerName !== bodyName) {
      console.error(
        `[replica ${name}] REJECT header/body mismatch: Mcp-Name=${headerName} body.params.name=${bodyName}`,
      );
      return c.json(
        {
          jsonrpc: "2.0",
          id: body.id ?? null,
          error: { code: -32001, message: "HeaderMismatch: Mcp-Name does not match body.params.name" },
        },
        400,
      );
    }
    console.error(
      `[replica ${name}] routing hint headers Mcp-Method=${headerMethod ?? "(absent)"} Mcp-Name=${headerName ?? "(absent)"} — decision below uses body.params.name=${bodyName} ONLY`,
    );

    const toolName = bodyName;
    const args = body.params?.arguments;
    const tier = tierFor(toolName);
    const call = {
      subject: principal,
      action: toolName,
      resource: body.params?.resource ?? null,
      agent: "agent:demo",
      arguments: args ?? null,
    };

    if (tier !== "critical") {
      console.error(`[replica ${name}] tier=${tier} for ${toolName} — passthrough, no approval needed`);
      const upstream = await fetch(`${upstreamUrl}/execute`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: toolName, arguments: args }),
      }).then((r) => r.json());
      return c.json({
        jsonrpc: "2.0",
        id: body.id ?? null,
        result: { resultType: "success", ...upstream.result },
      });
    }

    const { requestState, approvalId, callHash, sizeBytes } = mintRequestState(
      { call, principal },
      key,
    );
    console.error(
      `[replica ${name}] tier=critical for ${toolName} — minted requestState (approvalId=${approvalId}, callHash=${callHash}, requestState is ${sizeBytes} bytes base64url) — NOT held in this process's memory`,
    );
    return c.json({
      jsonrpc: "2.0",
      id: body.id ?? null,
      result: {
        resultType: "input_required",
        inputRequests: {
          approval: {
            type: "elicitation",
            message: `Approve ${toolName}? (approvalId=${approvalId})`,
          },
        },
        requestState,
      },
    });
  });

  app.post("/mcp/resume", async (c) => {
    const body = await c.req.json();
    const currentPrincipal = c.req.header("x-principal") ?? "unknown";
    const { requestState, inputResponses } = body;

    let decoded;
    try {
      decoded = verifyAndDecrypt({ requestState, currentPrincipal }, key);
    } catch (err) {
      const message = err instanceof RequestStateError ? err.message : "internal error";
      console.error(`[replica ${name}] RESUME REJECTED (principal=${currentPrincipal}): ${message}`);
      return c.json(
        { jsonrpc: "2.0", id: body.id ?? null, error: { code: -32002, message } },
        403,
      );
    }

    const { approvalId, call, callHash } = decoded;
    console.error(
      `[replica ${name}] RESUME OK — reconstructed pending call from requestState alone (approvalId=${approvalId}, callHash=${callHash}, action=${call.action}); this process never held it in memory`,
    );

    const approved = inputResponses?.approval === "approve";
    if (!approved) {
      console.error(`[replica ${name}] human denied approvalId=${approvalId}`);
      return c.json({
        jsonrpc: "2.0",
        id: body.id ?? null,
        result: { resultType: "denied", approvalId },
      });
    }

    const upstream = await fetch(`${upstreamUrl}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: call.action, arguments: call.arguments }),
    }).then((r) => r.json());
    console.error(`[replica ${name}] executed upstream call for approvalId=${approvalId}`);

    return c.json({
      jsonrpc: "2.0",
      id: body.id ?? null,
      result: { resultType: "success", approvalId, resolvedBy: name, ...upstream.result },
    });
  });

  return app;
}

// Executed as its own OS process (see run-demo.mjs), one instance per
// replica, each with its own independent copy of the shared key loaded
// from its own environment — no module-level state is shared between the
// two invocations because they are, structurally, two separate `node`
// processes.
const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const name = process.env.REPLICA_NAME ?? "?";
  const port = Number(process.env.PORT ?? 0);
  const key = loadSharedKey(process.env.SHARED_SECRET_HEX ?? "");
  const upstreamUrl = process.env.UPSTREAM_URL ?? "http://localhost:4300";
  const app = createReplicaApp({ name, key, upstreamUrl });
  serve({ fetch: app.fetch, port }, (info) => {
    console.error(`[replica ${name}] listening on :${info.port} (upstream=${upstreamUrl})`);
  });
}
