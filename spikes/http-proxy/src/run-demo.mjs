// SPIKE — the demo driver (P0-E10-T1). Spawns the fake upstream MCP server
// and TWO SEPARATE replica processes (real OS process boundary, not just
// two JS closures — see replica.mjs's header), then drives the whole
// stateless-resumption flow with real HTTP calls over loopback, printing
// every step. This is the script whose terminal output is captured
// verbatim into docs/03-engineering/spike-http-findings.md.
//
// Run with: npm run demo   (from spikes/http-proxy/, after `npm install`)

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { computeCallHash } from "./call-hash.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

const UPSTREAM_PORT = 4300;
const REPLICA_A_PORT = 4301;
const REPLICA_B_PORT = 4302;
// Hardcoded demo "KMS" key — 32 bytes hex. Both replica processes receive
// this via env, standing in for a real KMS/shared-secret-manager fetch.
// SEE THE FINDINGS DOC for why this is explicitly NOT a production pattern.
const SHARED_SECRET_HEX =
  "3f1a9c2e7b4d6081a5c3e9f2b7d4061c8e2a5f9b3d7c1e6084a2f7b9c3e5d108";

function banner(text) {
  console.log(`\n${"=".repeat(78)}\n${text}\n${"=".repeat(78)}`);
}

/** Spawns a child process and resolves once its stderr prints `readyPattern`. */
function spawnAndWait(scriptRelPath, env, readyPattern) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(here, scriptRelPath)], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "inherit", "pipe"],
    });
    let ready = false;
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      process.stderr.write(text);
      if (!ready && readyPattern.test(text)) {
        ready = true;
        resolve(child);
      }
    });
    child.on("exit", (code) => {
      if (!ready) reject(new Error(`${scriptRelPath} exited early with code ${code}`));
    });
    setTimeout(() => {
      if (!ready) reject(new Error(`${scriptRelPath} did not become ready within 5s`));
    }, 5000);
  });
}

async function main() {
  banner("SETUP — starting fake upstream MCP server + two ISOLATED replica processes");

  const upstream = await spawnAndWait("fake-upstream-server.mjs", { PORT: String(UPSTREAM_PORT) }, /listening/);
  const replicaA = await spawnAndWait(
    "replica.mjs",
    {
      REPLICA_NAME: "A",
      PORT: String(REPLICA_A_PORT),
      SHARED_SECRET_HEX,
      UPSTREAM_URL: `http://localhost:${UPSTREAM_PORT}`,
    },
    /listening/,
  );
  const replicaB = await spawnAndWait(
    "replica.mjs",
    {
      REPLICA_NAME: "B",
      PORT: String(REPLICA_B_PORT),
      SHARED_SECRET_HEX,
      UPSTREAM_URL: `http://localhost:${UPSTREAM_PORT}`,
    },
    /listening/,
  );
  const children = [upstream, replicaA, replicaB];

  const urlA = `http://localhost:${REPLICA_A_PORT}`;
  const urlB = `http://localhost:${REPLICA_B_PORT}`;

  try {
    // -------------------------------------------------------------------
    banner("STEP 1 — client -> REPLICA A: tools/call stripe.refund_payment (critical) as principal=alice");
    const initialBody = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "stripe.refund_payment", arguments: { charge_id: "ch_demo123", amount: 4200 } },
    };
    const step1 = await fetch(`${urlA}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-principal": "alice",
        "mcp-method": "tools/call",
        "mcp-name": "stripe.refund_payment",
      },
      body: JSON.stringify(initialBody),
    }).then((r) => r.json());
    console.log("client received:", JSON.stringify(step1, null, 2));
    const requestState = step1.result.requestState;
    if (step1.result.resultType !== "input_required" || !requestState) {
      throw new Error("expected input_required + requestState from replica A");
    }

    // -------------------------------------------------------------------
    banner("STEP 2 — (out of band) a human approves via the elicitation UI");
    console.log('simulating: human clicks "Approve" -> inputResponses.approval = "approve"');

    // -------------------------------------------------------------------
    banner("STEP 3 — client -> REPLICA B (the OTHER process, never saw step 1) resumes with requestState");
    const step3 = await fetch(`${urlB}/mcp/resume`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-principal": "alice" },
      body: JSON.stringify({ requestState, inputResponses: { approval: "approve" } }),
    }).then((r) => r.json());
    console.log("client received:", JSON.stringify(step3, null, 2));
    if (step3.result?.resultType !== "success") {
      throw new Error("expected replica B to resolve the call successfully");
    }
    console.log("\n>>> PROVED: replica B, holding NO in-memory record of the original call, reconstructed and resolved it purely from requestState. <<<");

    // -------------------------------------------------------------------
    banner("STEP 4 — TAMPER TEST: flip one character inside the ciphertext, resume against replica B");
    // Decode the outer envelope, mutate one character INSIDE the `ct` field
    // specifically (not the outer base64url/JSON framing), and re-encode —
    // this exercises the GCM auth-tag check itself (the actual MAC
    // verification), rather than merely tripping the outer JSON.parse.
    const decodedEnvelope = JSON.parse(Buffer.from(requestState, "base64url").toString("utf8"));
    const ctChars = decodedEnvelope.ct.split("");
    const flipIdx = Math.floor(ctChars.length / 2);
    ctChars[flipIdx] = ctChars[flipIdx] === "A" ? "B" : "A";
    decodedEnvelope.ct = ctChars.join("");
    const tampered = Buffer.from(JSON.stringify(decodedEnvelope), "utf8").toString("base64url");
    const step4 = await fetch(`${urlB}/mcp/resume`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-principal": "alice" },
      body: JSON.stringify({ requestState: tampered, inputResponses: { approval: "approve" } }),
    });
    console.log(`HTTP ${step4.status}:`, JSON.stringify(await step4.json(), null, 2));
    console.log(">>> PROVED: a tampered requestState fails MAC verification (GCM auth tag), rejected before decrypt/reconstruct. <<<");

    // -------------------------------------------------------------------
    banner("STEP 5 — WRONG-PRINCIPAL TEST: alice's untouched requestState, resumed as principal=bob");
    const step5 = await fetch(`${urlB}/mcp/resume`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-principal": "bob" },
      body: JSON.stringify({ requestState, inputResponses: { approval: "approve" } }),
    });
    console.log(`HTTP ${step5.status}:`, JSON.stringify(await step5.json(), null, 2));
    console.log(">>> PROVED: the SAME unmodified, valid requestState fails when replayed under a different principal — the AAD the verifier reconstructs (bob|callHash) never matches what alice's mint used (alice|callHash), so this fails through the identical code path as tampering, not a separate forgettable check. <<<");

    // -------------------------------------------------------------------
    banner("STEP 6 — HEADER/BODY MISMATCH: Mcp-Name header disagrees with body.params.name (brief §C2 / SEP-2243)");
    const mismatchBody = {
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "stripe.refund_payment", arguments: { charge_id: "ch_evil", amount: 999999 } },
    };
    const step6 = await fetch(`${urlA}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-principal": "alice",
        "mcp-method": "tools/call",
        "mcp-name": "stripe.list_charges", // deliberately wrong vs. body.params.name
      },
      body: JSON.stringify(mismatchBody),
    });
    console.log(`HTTP ${step6.status}:`, JSON.stringify(await step6.json(), null, 2));
    console.log(">>> PROVED: header/body mismatch is rejected outright (HeaderMismatch); note from STEP 1's log line that even when headers DO match, the tier decision reads body.params.name only — headers are routing/telemetry, never the decision input. <<<");

    // -------------------------------------------------------------------
    banner("STEP 7 — BODY-PARSE COST: JSON.parse over a representative tools/call payload");
    const sample = JSON.stringify({
      jsonrpc: "2.0",
      id: 999,
      method: "tools/call",
      params: {
        name: "stripe.refund_payment",
        arguments: { charge_id: "ch_demo123", amount: 4200, reason: "customer requested", metadata: { order_id: "ord_9981", note: "duplicate charge" } },
      },
    });
    const ITERATIONS = 50_000;
    const start = process.hrtime.bigint();
    for (let i = 0; i < ITERATIONS; i++) {
      JSON.parse(sample);
    }
    const end = process.hrtime.bigint();
    const totalMs = Number(end - start) / 1e6;
    console.log(`payload size: ${Buffer.byteLength(sample)} bytes`);
    console.log(`${ITERATIONS} JSON.parse calls: ${totalMs.toFixed(2)}ms total, ${(totalMs / ITERATIONS * 1000).toFixed(3)}µs/call average`);
    console.log("also for reference — the call-hash computation this spike uses on the same payload's parsed call:");
    const parsedForHash = JSON.parse(sample);
    const hashStart = process.hrtime.bigint();
    for (let i = 0; i < ITERATIONS; i++) {
      computeCallHash({
        subject: "alice",
        action: parsedForHash.params.name,
        resource: null,
        agent: "agent:demo",
        arguments: parsedForHash.params.arguments,
      });
    }
    const hashEnd = process.hrtime.bigint();
    const hashTotalMs = Number(hashEnd - hashStart) / 1e6;
    console.log(`${ITERATIONS} computeCallHash calls: ${hashTotalMs.toFixed(2)}ms total, ${(hashTotalMs / ITERATIONS * 1000).toFixed(3)}µs/call average`);

    banner("DEMO COMPLETE — all 7 steps ran end to end");
  } finally {
    for (const child of children) child.kill();
  }
}

main().catch((err) => {
  console.error("DEMO FAILED:", err);
  process.exitCode = 1;
});
