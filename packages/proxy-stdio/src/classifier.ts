/**
 * @knotrust/proxy-stdio — the classifier SEAM (P0-E5-T1, ruling R59; extended
 * P0-E5-T2, ruling R63).
 *
 * This is the single extension point the architecture's §4.1 data-flow diagram
 * names:
 *
 *     line framer → CLASSIFIER → [ adapter → core | pass-through ]
 *
 * Every JSON-RPC message crossing the proxy, in either direction, is handed to
 * a {@link ClassifierHook} which returns a {@link ClassifyResult} telling the
 * relay what to do with it. In P0-E5-T1 the ONLY action was `"passthrough"`
 * with no further capability: the proxy was a byte/shape-faithful transparent
 * relay with no interception or enforcement. The seam exists, typed, so
 * follow-on tasks can hook it with ZERO changes to the relay's transport
 * plumbing:
 *
 * - **P0-E5-T2 (tools/list capture, THIS extension):** observes `tools/list`
 *   RESULTS (`direction: "server_to_client"`) to snapshot/annotate the
 *   advertised tool set (rug-pull / annotation-trust surface) — see
 *   `tool-inventory.ts`. Critically, this does NOT need a new `action`
 *   variant: R63 ruled that observation is a pure SIDE EFFECT layered onto
 *   the existing `"passthrough"` action (see {@link ClassifyResult.observe}
 *   below) rather than a new routing decision, because forwarding behavior
 *   for `tools/list` is unchanged (still byte/shape-faithful passthrough) —
 *   only a decoupled, best-effort side channel is added.
 * - **P0-E5-T3 (tools/call enforcement):** will classify `tools/call` REQUESTS
 *   (`direction: "client_to_server"`) into a KnoTrust `DecisionRequest`, and —
 *   on a deny/needs-approval outcome — return a NON-passthrough action instead
 *   of forwarding, synthesizing the JSON-RPC response itself. THAT is what
 *   will actually widen `ClassifyResult` into a discriminated union (adding
 *   e.g. `{ action: "respond"; message }`). Because the relay switches
 *   exhaustively on `result.action` (see `proxy.ts`), adding a variant is a
 *   compile error until the relay handles it — the seam cannot be extended
 *   silently.
 *
 * See {@link composeClassifiers} for how a T2-style observational hook and a
 * future T3-style enforcement hook layer together without either one having
 * to know about the other.
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

/**
 * One JSON-RPC 2.0 message as it crosses the proxy. Aliased to the official
 * SDK's inferred `JSONRPCMessage` union (request | notification | success
 * response | error response) so the hook gets fully-typed access to `id` /
 * `method` / `params` / `result` / `error` — this is the typed-`tools/call`
 * access R58 chose the SDK-composition pattern for, available to T2/T3 at the
 * seam without the proxy itself parsing anything.
 */
export type JsonRpcMessage = JSONRPCMessage;

/**
 * Which way a message is travelling, from the proxy's point of view.
 * - `"client_to_server"`: the real MCP client → proxy → child server (requests,
 *   notifications the client sends).
 * - `"server_to_client"`: the child server → proxy → real MCP client
 *   (responses, server notifications, server-initiated requests such as
 *   sampling/`roots`/elicitation).
 */
export type ClassifyDirection = "client_to_server" | "server_to_client";

/**
 * What the relay should do with a classified message. The sole ROUTING
 * variant remains `"passthrough"` (T3 will add further variants — see this
 * module's doc-comment; each new variant forces a matching case in the
 * relay's exhaustive switch).
 *
 * `observe` (R63, P0-E5-T2) is NOT a routing decision — the message is
 * forwarded exactly as `"passthrough"` always meant, byte/shape-faithfully,
 * regardless of whether `observe` is present. It is an optional, decoupled
 * side-effect callback the relay invokes AFTER handing the message to the
 * opposite transport (see `proxy.ts`'s `relay()`), with the SAME message
 * object, unmodified. This is deliberately a callback returned alongside the
 * result — not something `classify()` does inline itself — because
 * `classify()` must stay pure/synchronous/I-O-free (unchanged contract, see
 * `ClassifierHook` below), while a real observer (P0-E5-T2's tools/list
 * capture: local file I/O to persist a per-server tool inventory) genuinely
 * needs to do work. Splitting "decide" from "act on the decision" is what
 * lets `observe` do that work without violating `classify()`'s own contract.
 *
 * Calling `observe` can never alter what was already sent: by the time the
 * relay invokes it, the message is already forwarded (or queued to be) —
 * "the forwarded bytes must be identical" (R63) holds unconditionally,
 * `observe` or not. A throw from `observe` is caught by the relay and logged,
 * never allowed to affect forwarding or crash the proxy (defense in depth —
 * see `proxy.ts`).
 */
export type ClassifyResult = {
  readonly action: "passthrough";
  readonly observe?: (msg: JsonRpcMessage) => void;
};

/**
 * The SEAM (R59): `(msg, direction) => ClassifyResult`. Pure and synchronous —
 * classification must not itself perform I/O or reorder the stream; the relay
 * calls it inline for every message and acts on the result immediately, so
 * ordering and real-time delivery of notifications is preserved. A hook MAY
 * carry its own internal state across calls (e.g. P0-E5-T2's tools/list
 * pagination bookkeeping) — "pure" here means "no I/O and no externally
 * observable side effect other than its return value," not "stateless
 * closure"; mutating an in-memory `Map` the hook itself owns is fine, doing a
 * `readFileSync` is not (that belongs in `observe`, see `ClassifyResult`).
 */
export type ClassifierHook = (
  msg: JsonRpcMessage,
  direction: ClassifyDirection,
) => ClassifyResult;

/**
 * The P0-E5-T1 default hook: classify EVERYTHING as passthrough, with no
 * `observe`. This is what makes the proxy a transparent relay — `initialize`,
 * `tools/list`, `tools/call`, `ping`, `resources/*`, `prompts/*`, sampling,
 * every notification, and any method the SDK does not model all pass through
 * untouched. T2/T3 supply their own hooks via `createStdioProxy`'s `onClassify`
 * option (or the dedicated `toolInventory` option, for T2 — see `proxy.ts`);
 * this remains the fallback for every message they don't intercept.
 */
export const defaultClassifier: ClassifierHook = () => ({
  action: "passthrough",
});

/**
 * Composes two classifier hooks so both get a chance to react to every
 * message crossing the proxy, without either having to know the other
 * exists. `primary`'s routing decision always wins when it is anything other
 * than plain `"passthrough"` (e.g. a future T3 enforcement hook denying or
 * synthesizing a response) — `secondary` never gets a chance to override
 * that, and is not even consulted in that case (there is nothing left to
 * observe: the message was not forwarded as-is). When `primary` DOES return
 * `"passthrough"`, `secondary` is also consulted purely for its own
 * bookkeeping/`observe` side effect; if `secondary` itself returns a
 * non-passthrough action (unexpected for an observational hook, but not
 * disallowed by the type), that is honored too rather than silently
 * discarded — this composer doesn't know what a future action variant means,
 * so it must not assume ignoring one is safe. When both hooks return
 * `"passthrough"` with an `observe` callback, the two are chained (`primary`'s
 * runs first) rather than one clobbering the other.
 *
 * `createStdioProxy` uses this to layer P0-E5-T2's tools/list-observing hook
 * (`toolInventory` option) on top of whatever `onClassify` hook (or the
 * default) is otherwise in effect — see `proxy.ts`.
 */
export function composeClassifiers(
  primary: ClassifierHook,
  secondary: ClassifierHook,
): ClassifierHook {
  return (msg, direction) => {
    const primaryResult = primary(msg, direction);
    if (primaryResult.action !== "passthrough") {
      return primaryResult;
    }
    const secondaryResult = secondary(msg, direction);
    if (secondaryResult.action !== "passthrough") {
      return secondaryResult;
    }
    const observe = composeObserve(
      primaryResult.observe,
      secondaryResult.observe,
    );
    return observe !== undefined
      ? { action: "passthrough", observe }
      : { action: "passthrough" };
  };
}

function composeObserve(
  a: ((msg: JsonRpcMessage) => void) | undefined,
  b: ((msg: JsonRpcMessage) => void) | undefined,
): ((msg: JsonRpcMessage) => void) | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return (msg) => {
    a(msg);
    b(msg);
  };
}
