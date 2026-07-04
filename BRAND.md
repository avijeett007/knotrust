# KnoTrust brand

This is the source of truth for the KnoTrust mark, color, and type system.
Assets referenced below live in [`assets/`](assets/).

## The mark: concept

**KnoTrust** is a knot: two rounded bands hooked through one another like two
links caught mid-cinch.

- The **ink band** is the policy/grant boundary — the thing KnoTrust
  evaluates against.
- The **gold band** is the tool call — the thread trying to pass through.
- They aren't drawn as a flat overlap. The stroke order alternates at the two
  crossings (over, then under, then the small ink "weave" patch restores the
  order at the top) so it reads as an actual interlock, not two circles
  Venn-style. That alternation *is* the idea: nothing crosses from one loop
  to the other except through that one seam — and the seam is where
  KnoTrust sits, in the stdio path between an agent and the tool it's
  calling.

Two equal, same-size loops (not one large "container" ring and one small
"detail") on purpose: the product doesn't put the grant above the call in a
hierarchy, it binds them at a shared checkpoint. The whole thing is rotated
32° off the horizontal so it doesn't sit flat and read as an infinity symbol
lying on its side — a real, deliberate risk called out and corrected during
design (the first flat, unrotated draft looked exactly like a stretched ∞,
which is a cliché this brand doesn't want).

Two things this mark deliberately is **not**:

- **Not a padlock.** Every "security tool" logo is a padlock. A knot is the
  more specific, more accurate metaphor for what KnoTrust actually does —
  binds a call to a grant — and it's the literal etymology of the name
  ("Kno" + "Trust").
- **Not a wax seal / shield / badge.** Those read as enterprise-compliance
  theater. This is two bold, confident bands with real craft in the
  crossing — closer to the polish of Vercel, Tailwind, or 1Password's marks
  than to a GRC vendor's shield.

The favicon (`assets/favicon.svg`) is the same geometry with a thicker
stroke and a wider weave patch — a legibility optimization for 16–32px, not
a different mark.

## Color

Ink + gold, not blue. Blue is the default for every dev tool; gold reads as
*signed / certified / a seal on a document* — appropriate for a tool whose
entire job is signed grants — and doubles as an amber "hold for approval"
signal, which is literally what KnoTrust does to risky tool calls.

| Token | Hex | Use |
|---|---|---|
| `--knot-ink` | `#14131C` | Primary. The grant loop, body text and the wordmark on light surfaces. |
| `--knot-gold` | `#E7A93A` | Accent. The call-thread loop, links, focus states, highlights — on both light and dark surfaces. |
| `--knot-paper` | `#F5F4F0` | Ink's swap-in on dark surfaces: the grant loop and wordmark when the background is dark. |
| `--knot-surface-light` | `#FFFFFF` | Page background, light mode. |
| `--knot-surface-dark` | `#0B0B10` | Page background, dark mode. |
| `--knot-ink-muted` | `#4B4A52` | Secondary text on light surfaces (captions, metadata). |
| `--knot-mist` | `#9C9B97` | Secondary text on **dark** surfaces only (see contrast note below). |
| `--knot-line` | `#E7E5DF` | Hairline borders / dividers on light surfaces. |
| `--knot-line-dark` | `#232229` | Hairline borders / dividers on dark surfaces. |
| `--knot-ghost` | `#1B1A22` | Decorative background texture on dark surfaces only (e.g. the oversized mark bleed in `social-preview.svg`). Never used for content. |

**Contrast (WCAG 2.1, measured):**

| Pair | Ratio | Passes |
|---|---|---|
| `--knot-ink` on `--knot-surface-light` | 18.4:1 | AAA, any text size |
| `--knot-paper` on `--knot-surface-dark` | 17.8:1 | AAA, any text size |
| `--knot-gold` on `--knot-surface-dark` | 9.5:1 | AAA, any text size |
| `--knot-gold` on `--knot-surface-light` | 2.1:1 | **Fails** — gold is for graphics/large accents on light backgrounds, never body text |
| `--knot-mist` on `--knot-surface-dark` | 7.1:1 | AA/AAA, normal text |
| `--knot-mist` on `--knot-surface-light` | 2.8:1 | **Fails** — use `--knot-ink-muted` on light instead |
| `--knot-ink-muted` on `--knot-surface-light` | 8.8:1 | AAA, normal text |

Copy-pasteable CSS:

```css
:root {
  --knot-ink: #14131C;
  --knot-gold: #E7A93A;
  --knot-paper: #F5F4F0;
  --knot-surface-light: #FFFFFF;
  --knot-surface-dark: #0B0B10;
  --knot-ink-muted: #4B4A52;
  --knot-mist: #9C9B97;
  --knot-line: #E7E5DF;
  --knot-line-dark: #232229;
  --knot-ghost: #1B1A22;
}

@media (prefers-color-scheme: dark) {
  :root {
    --knot-fg: var(--knot-paper);
    --knot-bg: var(--knot-surface-dark);
    --knot-fg-muted: var(--knot-mist);
    --knot-border: var(--knot-line-dark);
  }
}
@media (prefers-color-scheme: light) {
  :root {
    --knot-fg: var(--knot-ink);
    --knot-bg: var(--knot-surface-light);
    --knot-fg-muted: var(--knot-ink-muted);
    --knot-border: var(--knot-line);
  }
}
```

## Type

**Wordmark artwork** (`assets/logo-wordmark.svg`): set in a bold geometric
grotesque (built from system **DIN Alternate Bold**), then outlined to static
paths. It's shipped as vector artwork, not live `<text>`, specifically so it
renders identically on GitHub, in browsers, and in any doc generator — no
font file is required or embedded to view it. Mixed case ("KnoTrust", not
"KNOTRUST" or "knotrust") is deliberate: it's what keeps the "Kno" + "Trust"
seam in the name visible, the same device GitHub and PayPal use for compound
names.

**Live text on the web/README** (headings, body, UI) — use a system stack
that approximates the same geometric-grotesque character, since DIN
Alternate isn't a standard web font:

```css
:root {
  --knot-font-display: "Inter", "Söhne", "Helvetica Neue", Arial, sans-serif;
  --knot-font-body: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  --knot-font-mono: ui-monospace, "SF Mono", Menlo, Consolas,
    "Liberation Mono", monospace;
}
```

`--knot-font-mono` is not an afterthought: KnoTrust is a stdio proxy/CLI, and
the social-preview tagline is deliberately set in monospace (SF Mono) against
the bold display wordmark — a small, real nod to the terminal/audit-log
register the product actually lives in. Reach for it for anything
code-adjacent (flags, config keys, log lines) alongside the display face.

## Spacing & clear space

- **Clear space around the mark** (any size): reserve empty margin on all
  four sides equal to at least the width of one band's stroke at that
  rendering. At the reference 512×512 artwork (`70`-unit stroke), that's a
  minimum ~70-unit margin — already built into `logo.svg`'s canvas. Don't
  crop tighter than that when placing it next to other content.
- **Wordmark lockup** (`logo-wordmark.svg`): the icon-to-wordmark gap and
  outer padding are baked into the artwork's viewBox (`1592×380`, 40-unit
  padding on all sides). Scale the whole file uniformly; don't rebuild the
  gap at a different ratio.
- **Minimum sizes**: mark 16px (favicon floor); prefer 24px+ for in-UI icons.
  Wordmark: don't render narrower than ~120px wide, the letterforms start
  to close up below that.

## Do / Don't

**Do**

- Match the variant to the surface: `logo.svg` / `logo-wordmark.svg` (ink)
  on light backgrounds, `logo-dark.svg` / `logo-wordmark-dark.svg` (paper)
  on dark ones.
- Keep the ink/gold pairing exactly as specified — it's as much the brand
  as the shape.
- Scale the mark and wordmark uniformly (lock the aspect ratio).
- Use `--knot-gold` freely for accents, links, and focus rings on dark
  surfaces; use it sparingly and only decoratively on light ones (see the
  contrast table).

**Don't**

- Don't recolor the loops to arbitrary brand-adjacent colors (no blue, no
  green "success" tinting) — ink and gold are the mark.
- Don't add drop shadows, bevels, gradients, or outlines to the mark. It's
  flat, and that's final.
- Don't separate the two loops, rotate them independently, or "unlock" the
  interlock for a decorative effect.
- Don't place the ink (light-surface) mark on a dark background or the
  paper (dark-surface) mark on a light one — it either disappears or looks
  like a mistake.
- Don't retype "KnoTrust" in a live font for anything that needs to match
  the wordmark exactly (headers, badges) — use the outlined SVG. Live
  `--knot-font-display` text is for surrounding copy, not the logotype
  itself.

## Files

| File | What it is |
|---|---|
| `assets/logo.svg` | Mark only, light-surface colors. |
| `assets/logo-dark.svg` | Mark only, dark-surface colors. |
| `assets/favicon.svg` | Mark, thicker/simplified for 16–32px. |
| `assets/favicon.png` | Rasterized favicon, 48×48. |
| `assets/icon-512.png` | Rasterized mark, 512×512, transparent (social/app icon). |
| `assets/logo-wordmark.svg` | Mark + "KnoTrust" lockup, light-surface colors. |
| `assets/logo-wordmark-dark.svg` | Mark + "KnoTrust" lockup, dark-surface colors. |
| `assets/social-preview.svg` / `.png` | GitHub social-preview / OG card, 1280×640. |
