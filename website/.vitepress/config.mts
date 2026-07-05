import { defineConfig } from "vitepress";

// GitHub Pages project-site base. This repo is published as
// <owner>/knotrust, served at https://<owner>.github.io/knotrust/ — change
// only if the repo is ever renamed or moved to a different owner/org.
const BASE = "/knotrust/";

// Confirm this against the actual GitHub org/repo before launch — see the
// orchestrator handoff notes. Used for socialLinks, editLink, and the OG image URL.
const REPO = "https://github.com/avijeett007/knotrust";
const SITE_ORIGIN = "https://avijeett007.github.io";

export default defineConfig({
  base: BASE,
  title: "KnoTrust",
  description:
    "Take back control of what your AI agents can do. KnoTrust auto-allows the safe actions, holds risky ones for your approval, and logs everything — local-first, open-source, and portable across Claude, Codex, and any MCP agent.",
  lastUpdated: true,
  cleanUrls: true,

  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: `${BASE}favicon.svg` }],
    ["link", { rel: "icon", type: "image/png", sizes: "48x48", href: `${BASE}favicon.png` }],
    ["meta", { name: "theme-color", content: "#E7A93A" }],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:site_name", content: "KnoTrust" }],
    ["meta", { property: "og:title", content: "KnoTrust — stop trusting your AI agents blindly" }],
    [
      "meta",
      {
        property: "og:description",
        content:
          "Take back control of what your AI agents can do: auto-allow safe actions, hold risky ones for a human's approval, and keep an audit trail of everything. Local-first and open-source.",
      },
    ],
    ["meta", { property: "og:image", content: `${SITE_ORIGIN}${BASE}social-preview.png` }],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
    ["meta", { name: "twitter:image", content: `${SITE_ORIGIN}${BASE}social-preview.png` }],
  ],

  themeConfig: {
    logo: { src: "/logo-wordmark.svg", alt: "KnoTrust" },
    siteTitle: false,

    nav: [
      { text: "Guide", link: "/guide/introduction" },
      { text: "CLI Reference", link: "/reference/cli" },
      { text: "Security", link: "/security" },
      { text: "Architecture", link: "/architecture" },
      { text: "FAQ", link: "/faq" },
    ],

    sidebar: [
      {
        text: "Guide",
        items: [
          { text: "Introduction", link: "/guide/introduction" },
          { text: "Installation & Quickstart", link: "/guide/installation" },
          { text: "Core Concepts", link: "/guide/core-concepts" },
          { text: "Configuration", link: "/guide/configuration" },
        ],
      },
      {
        text: "Reference",
        items: [{ text: "CLI Reference", link: "/reference/cli" }],
      },
      {
        text: "Security",
        items: [{ text: "Security Model & Threat Boundaries", link: "/security" }],
      },
      {
        text: "Architecture",
        items: [{ text: "System Architecture", link: "/architecture" }],
      },
      {
        text: "FAQ",
        items: [{ text: "Frequently Asked Questions", link: "/faq" }],
      },
    ],

    socialLinks: [{ icon: "github", link: REPO }],

    editLink: {
      pattern: `${REPO}/edit/main/website/:path`,
      text: "Edit this page on GitHub",
    },

    search: {
      provider: "local",
    },

    footer: {
      message: "Released under the Apache License 2.0.",
      copyright: "Copyright © 2026 Kno2gether Labs Ltd",
    },

    outline: {
      level: [2, 3],
    },
  },
});
