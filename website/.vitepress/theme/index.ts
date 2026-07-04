// KnoTrust docs theme — extends the default VitePress theme with brand CSS
// only. No custom components: the default theme's layout (home hero,
// features grid, doc/sidebar/nav) is used as-is, themed via CSS custom
// properties in ./custom.css (see BRAND.md at the repo root for the token
// source of truth).
import type { Theme } from "vitepress";
import DefaultTheme from "vitepress/theme";
import "./custom.css";

export default {
  extends: DefaultTheme,
} satisfies Theme;
