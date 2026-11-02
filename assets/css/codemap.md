# assets/css/
## Responsibility
Site CSS overrides for the terminal/editorial theme. `custom.css` (2,127 lines) is appended last in the `hugo-brewm.css` bundle, so it restyles hugo-brewm without forking it. `typeface/` holds the self-hosted OpenDyslexic override (own codemap). All other `css/**` paths resolve to `themes/hugo-brewm/assets/css/`.

## Design
**Tokens** (`:root`, 53–70): `--sf`/`--rm` = self-hosted Atkinson Hyperlegible (faces declared 12–42), `--tt` = native system monospace (no webfont), `--braille-font` for the ASCII portrait, `--hl` pink highlight, `--g18`/`--g18s` tan hairlines, `--term-panel` `#111`, `--scan` scanline tint. The palette (`--ac`, `--bg`, `--fg`, `--mid`) is not redefined — the theme renders it from `site.Params.style`. `--max-width` is re-declared at 866–886 (60 → 84 → 92 → 100rem) and `.notes-shell` adds scoped `--notes-muted` (904).

**Dark-only enforcement** (72–103): `color-scheme: dark` on `html, body`; hides `#dwclock`, `.grain`, and `#lightSwitch` + label so the theme's scheme toggle cannot produce a light page. Contrast, font-size, and OpenDyslexic controls remain.

**Section map** (approximate, following the file's banners):
- 1–70 — header comment, `@font-face` for Atkinson + Lain Braille (U+2800–28FF), design tokens.
- 105–148 — wordmark: kills the SVG animation, sets `--tt`/`--fg`; long selector list forces monospace on metadata, pagination, taxonomy.
- 150–299 — homepage hero: `.home-hero` grid, `.lain-art` braille portrait with scanlines, `lain-flip` (0.15 s steps), terminal lines, blinking `.cursor`.
- 301–390 — homepage log/feed: flat `.feed-item` rows, hairline rules, unclipped `.par`.
- 392–442 — tags/taxonomy: square chips, outline→accent hover.
- 444–489 — footer/contentinfo/licence, square share controls.
- 491–510 — Pagefind variable bridge (`--pagefind-ui-*` → site palette, radius 0).
- 512–706 — profile page: kicker/name/role, facts grid, timeline/education/certs, toolbox; `body:has(.profile-name)` tightens article top gap.
- 708–799 — homepage notes guide cards.
- 801–897 — responsive breakpoints (hero stack, profile grids) and the first `prefers-reduced-motion` block (cursor, portrait).
- 899–1032 — notes shell: two-column grid, sticky `.notes-nav` tree, active/current states. **Checklist pin/highlight**: `.notes-nav__checklist` (997–1028) static amber, glow off under `prefers-contrast: more` and in print.
- 1034–1110 — notes index headers, section titles, `.notes-cards`/`.notes-card`.
- 1112–1296 — notes content: full-width prose, zero indent, `.notes-toc`, GitBook `aside.note` variants, fold-out `details`, `mark`, checkbox `accent-color`, scrollable tables/pre.
- 1298–1449 — notes footer: tags, prev/next grid, credit, responsive nav collapse at 960/640 px.
- 1451–1470 — `.notes-figure`.
- 1472–1728 — notes refinements: sr-only `.pagefind-filter`, link underlines, `.notes-meta`/`.notes-updated`, **`.notes-attribution`** (1531–1537, mono muted), related list, code frames, `.notes-copy`, `.heading-anchor`, print rules.
- 1730–1746 — language arrow and search-input legibility fixes.
- 1748–1921 — notes code palette: forces the theme's dark Chroma variables under `body:not(.deuteranopia|protanopia|tritanopia|monochrome)`, then maps `.chroma` token classes to `--code-*`.
- 1923–1946 — slow dot field (`#background-body::before`, 240 s drift).
- 1948–1987 — **running-lain**: full-bleed 146 px sprite strip, `100vw` bleed via negative margin, 2560 px tile, pixelated, 0.3 s loop; `--notes` variant adds a top rule.
- 1989–2036 — reduced-motion/contrast/print suppression of the above, padding floor, `overflow-x: clip`.
- 2038–2127 — **`.ph-vars` placeholder bar** (2042–2122): panel, responsive field grid, mono inputs, clear button; **`.ph`** (2124) accent + dotted underline for substituted tokens.

**Overrides vs extends.** Overrides: feed cards, tags, footer, Pagefind theme vars, `--max-width`, and the dark Chroma palette. Extends (site-only classes absent from the theme): `.home-hero`, `.lain-art`, `.terminal-line`, `.notes-*`, `.profile-*`, `aside.note`, `.ph-vars`/`.ph`, `.running-lain`, `.heading-anchor`, `.notes-copy`.

## Flow
Cascade order is fixed by the bundle: theme base → font faces → conditional extras → `custom.css`. Inside `custom.css` the order is tokens → dark-only locks → page-level components → notes shell/content → refinements → code palette → decorative strips → media overrides (`max-width`, `prefers-reduced-motion`, `prefers-contrast`, `print`). Print rules hide navigation, copy buttons, anchors, and decorative strips so notes print as linear text.

## Integration
Loaded by `layouts/partials/head/css.html` as `resources.Get "css/custom.css"`, appended to `$order` and concatenated into `hugo-brewm.css`, then minified and `fingerprint "sha256"`-ed (production). Consumers: `layouts/notes/single.html` (`notes-shell`, `notes-article`, `ph-vars`, `notes-attribution`, `running-lain`), notes list/nav/related/prevnext partials, the homepage hero/guide partials, and the profile page. `themes/hugo-brewm/assets/css/media/print.css` is emitted separately and complements the print blocks here.
