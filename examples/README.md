# examples

`knotrust.config.ts` / `knotrust.config.yaml` / `knotrust.config.json` are one
semantically-identical trio (P0-E4-T2): a realistic small config with one
server (`github-mcp`), three tools spanning all three tiers with their
`source` markers, an envelope tier floor, and a sensitive-tier cache TTL
override. `packages/store` loads config via
[c12](https://github.com/unjs/c12) (`name: "knotrust"`) — `.ts`, `.yaml`,
and `.json` are all equally first-class; c12's bundled
[jiti](https://github.com/unjs/jiti) executes the `.ts` form directly, no
build step required.

`packages/store/src/config.test.ts`'s trio deep-equal test loads all three
files in this directory directly and asserts they normalize to the exact
same `KnotrustConfig` — keeping this trio honest. If you edit one file here,
edit its two siblings identically (or the sync test will fail).

See `packages/store/src/config.ts` (`KnotrustConfigSchema`) for the full
schema, and `golden-vectors/schemas/config.v1.schema.json` for its
language-neutral JSON Schema mirror.
