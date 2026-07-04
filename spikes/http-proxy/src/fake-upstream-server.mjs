// SPIKE — a tiny plain node:http server standing in for the real MCP tool
// server that sits behind the proxy (not a Hono app on purpose — this is
// the "FAKE HTTP MCP server" the brief describes, distinct from the
// replicas' own Hono reverse-proxy layer). Runs as its own OS process.
//
// One route: POST /execute { name, arguments } -> { ok: true, result }.
// No auth, no validation, no error handling — it is not what's under test.

import { createServer } from "node:http";

const port = Number(process.env.PORT ?? 4300);

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = createServer(async (req, res) => {
  if (req.method === "POST" && req.url === "/execute") {
    const raw = await readBody(req);
    const { name, arguments: args } = JSON.parse(raw);
    console.error(`[upstream] executing tool=${name} arguments=${JSON.stringify(args)}`);
    const result = {
      ok: true,
      result: {
        tool: name,
        executedAt: new Date().toISOString(),
        echoArguments: args,
        note: "fake upstream MCP server — not a real Stripe/anything call",
      },
    };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(result));
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
});

server.listen(port, () => {
  console.error(`[upstream] fake MCP HTTP server listening on :${port}`);
});
