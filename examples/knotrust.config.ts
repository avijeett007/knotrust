/**
 * Example KnoTrust config (P0-E4-T2) — semantically IDENTICAL to
 * knotrust.config.yaml and knotrust.config.json in this directory (see
 * README.md). One server, three tools spanning all three tiers with their
 * `source` markers, an envelope tier floor, and a sensitive cache TTL
 * override. All three files in this trio must normalize to the exact same
 * KnotrustConfig (packages/store/src/config.test.ts's trio deep-equal test
 * loads this file directly — keep it in sync with its siblings).
 *
 * Deliberately IMPORT-FREE: this file is loaded standalone (via c12, whose
 * bundled jiti executes it) from outside the pnpm workspace, and a real end
 * user copying it into their own project has the published `knotrust` CLI
 * installed, not this monorepo's internal `@knotrust/*` package names — so
 * it stays a plain, self-contained data literal (config must be data; see
 * `packages/store/src/config.ts`'s `KnotrustConfigSchema`) rather than
 * importing a `defineKnotrustConfig` helper.
 */
export default {
  version: 1,
  scope: "personal",
  identity: {
    subjectId: "avijeett007@gmail.com",
    subjectType: "user",
  },
  servers: {
    "github-mcp": {
      tools: {
        "github.create_issue": {
          tier: "routine",
          source: "annotation",
        },
        "github.close_issue": {
          tier: "sensitive",
          source: "pack",
          mapping: {
            resourceType: "github_issue",
            resourceId: "arguments.issue_number",
            properties: {
              repo: "arguments.repo",
            },
          },
        },
        "github.delete_repo": {
          tier: "critical",
          source: "user",
          explicitDeny: true,
        },
      },
    },
  },
  unknownToolTier: "sensitive",
  envelope: {
    tierFloors: {
      "github.create_issue": "sensitive",
    },
  },
  approvalTimeoutSeconds: 300,
  cacheTtlOverrides: {
    sensitive: 30,
  },
};
