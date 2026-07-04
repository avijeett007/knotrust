/**
 * P0-E11-T1 acceptance demonstration #2 (R56, ruling 2, bullet 2):
 *
 * "The chaos-profile stability run: seeded random delays + interleaved
 * `notifications/progress`/`notifications/message` during a passthrough
 * conversation, asserted to complete correctly — run it 100 consecutive
 * iterations in one test (loop with distinct seeds), all green... State the
 * total wall-time; if 100 in-process iterations are too slow for CI, keep
 * them in-process (not child-spawn) to stay fast and say so."
 *
 * This stays in-process throughout (no child_process spawn, no temp-file
 * I/O — `startFakeServer` is called WITHOUT `prepareChildCommand`): 100
 * real OS subprocess spawns would dominate wall time and make this an
 * unreasonably slow acceptance gate for CI. The baseline test
 * (`baseline.test.ts`) already proves the real-child-process path works;
 * this test's job is chaos-profile *stability*, which the in-process
 * transport exercises identically (same `buildFakeServer` core, same wire
 * message shapes — see `core.ts`'s module doc-comment on shared-core
 * factoring).
 *
 * Every iteration uses a distinct, logged seed (`BASE_SEED + i`). On
 * failure, the seed is embedded in the thrown error so the failing
 * iteration is independently reproducible outside this loop (R54 ruling 4).
 */
import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { FakeClient } from "../fake-client/client.js";
import { startFakeServer } from "../fake-server/start.js";
import type { FakeServerConfig, FakeToolDef } from "../fake-server/types.js";

function tool(name: string, overrides: Partial<FakeToolDef> = {}): FakeToolDef {
  return {
    name,
    inputSchema: { type: "object", properties: {} },
    ...overrides,
  };
}

const ITERATIONS = 100;
const BASE_SEED = 900_000;
// Generous ceiling for a slow CI runner; the point of staying in-process is
// that this comfortably finishes in low single-digit seconds locally.
const TEST_TIMEOUT_MS = 60_000;

async function runOneChaoticConversation(
  seed: number,
  useProgressToken: boolean,
): Promise<{ progressCount: number; messageCount: number }> {
  const config: FakeServerConfig = {
    serverInfo: { name: "knotrust-fake-server-chaos", version: "1.0.0" },
    tools: [
      tool("status", { description: "quick, undelayed tool" }),
      tool("chaotic-echo"),
    ],
    toolBehaviors: {
      "chaotic-echo": {
        delayMs: { min: 5, max: 25 },
        respond: { type: "echo" },
      },
    },
    chaos: { seed, interleaveNotifications: true, notificationBudget: 2 },
  };

  const started = await startFakeServer(config);
  const client = new FakeClient(started.inProcess.clientTransport);

  try {
    // A full passthrough-shaped conversation: initialize -> tools/list -> tools/call -> shutdown.
    await client.connect();
    const { tools } = await client.listAllTools();
    if (tools.length !== 2) {
      throw new Error(`expected 2 tools, got ${tools.length}`);
    }

    const args = { seed, iterationMarker: `chaos-${seed}` };
    const progressEvents: unknown[] = [];
    const result = await client.callTool(
      "chaotic-echo",
      args,
      useProgressToken
        ? {
            progressToken: `progress-${seed}`,
            onProgress: (p) => progressEvents.push(p),
          }
        : {},
    );

    const expectedText = JSON.stringify(args);
    const block = result.content[0];
    if (
      result.isError ||
      block?.type !== "text" ||
      block.text !== expectedText
    ) {
      throw new Error(
        `unexpected tools/call result: ${JSON.stringify(result)}`,
      );
    }

    return {
      progressCount: client.receivedNotificationsOf("notifications/progress")
        .length,
      messageCount: client.receivedNotificationsOf("notifications/message")
        .length,
    };
  } finally {
    await client.close();
    await started.close();
  }
}

describe("R56 acceptance — chaos-profile stability (100 consecutive seeded iterations, in-process)", () => {
  it(
    "completes 100 chaotic passthrough-shaped conversations correctly, with interleaved progress/message notifications",
    async () => {
      const startedAt = performance.now();
      let totalProgress = 0;
      let totalMessages = 0;

      for (let i = 0; i < ITERATIONS; i++) {
        const seed = BASE_SEED + i;
        // Alternate progress-token vs. plain calls so the run exercises
        // BOTH notifications/progress (token present) and
        // notifications/message (token absent, chaos-prng-gated) heartbeat
        // paths across the 100 iterations, per R56's "interleaved
        // notifications/progress/notifications/message" wording.
        const useProgressToken = i % 2 === 0;
        try {
          const { progressCount, messageCount } =
            await runOneChaoticConversation(seed, useProgressToken);
          totalProgress += progressCount;
          totalMessages += messageCount;
        } catch (error) {
          const cause =
            error instanceof Error ? error : new Error(String(error));
          throw new Error(
            `chaos iteration ${i} FAILED (seed=${seed}, useProgressToken=${useProgressToken}): ${cause.message}`,
            { cause },
          );
        }
      }

      const wallTimeMs = performance.now() - startedAt;
      // R56: "State the total wall-time". Also captured verbatim in the task report.
      console.info(
        `[P0-E11-T1 chaos acceptance] ${ITERATIONS} in-process iterations completed in ${wallTimeMs.toFixed(1)}ms ` +
          `(seeds ${BASE_SEED}..${BASE_SEED + ITERATIONS - 1}); ` +
          `observed ${totalProgress} notifications/progress and ${totalMessages} notifications/message across the run.`,
      );

      expect(totalProgress).toBeGreaterThan(0);
      expect(totalMessages).toBeGreaterThan(0);
    },
    TEST_TIMEOUT_MS,
  );
});
