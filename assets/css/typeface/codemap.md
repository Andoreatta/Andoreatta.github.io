# assets/css/typeface/
## Responsibility
Self-hosted OpenDyslexic `@font-face` override. It shadows `themes/hugo-brewm/assets/css/typeface/OpenDyslexic.css`, whose faces are fetched from `raw.githubusercontent.com/antijingoist/OpenDyslexic/master/...` — a floating branch, no integrity, one third-party request per reader who opts in. Here the four text faces come from the site origin.

## Design
- **Faces:** Regular, Italic, Bold, Bold-Italic (`OpenDyslexic.css` 11–57). `local()` is tried first, so an installed copy is used before any download. `font-display: swap` keeps text visible during load.
- **Metrics strategy:** every face carries `size-adjust: 83%`, `ascent-override: 106%`, `descent-override: 36%`. These match OpenDyslexic's large x-height to the Atkinson Hyperlegible body faces, so enabling the accessibility toggle does not reflow line height or shift baselines — only the glyph shapes change.
- **Files:** `static/fonts/opendyslexic/OpenDyslexic-Regular.woff2`, `-Italic`, `-Bold`, `-Bold-Italic`, plus `OFL.txt`. They are served verbatim (not through Hugo Pipes) at `/fonts/opendyslexic/…`, so there is no content hash — replacing a file requires a URL change to bust caches. `OFL.txt` ships beside them because the OFL requires the licence to travel with the font.
- **No `unicode-range`:** unlike the Lain Braille face in `custom.css`, these faces cover the full glyph set, so the whole woff2 is downloaded on first use.
- **Mono face:** `OpenDyslexicMono` (59–69) intentionally keeps the theme path `/css/fonts/OpenDyslexicMono-Regular.woff2`, which the theme's `static/` still publishes; only the four relocated text faces diverge. The theme's `accessibility.js` maps `body[data-font=OpenDyslexic]` to `--tt: OpenDyslexicMono`, so code blocks follow the toggle too.
- `:root { --od: 'OpenDyslexic' }` (71–73) keeps the theme variable contract; the theme's typesetting template uses `var(--od)`.
- **Theme bug fixed:** the theme's italic-700 face declares `local('OpenDyslexicMono')` while loading the Bold-Italic file; this override declares `local('OpenDyslexic Bold Italic')` and keeps the correct `font-style`/`font-weight`.
- **Failure mode:** if a woff2 is missing the browser falls through to `local()` or the next family in `--rm`/`--sf`; `font-display: swap` means no invisible text, and the metric overrides keep line boxes stable.

## Flow
1. The stylesheet is always part of the CSS bundle (not conditional), but the browser only requests a `.woff2` when a rendered element actually resolves to the `OpenDyslexic`/`OpenDyslexicMono` family.
2. The toggle sets `data-font="OpenDyslexic"` on `<body>`; theme `accessibility.js` then rewrites `--rm`, `--sf`, `--tt`, so body text and code switch at once.
3. Because `local()` precedes `url()`, machines with the font installed make no network request at all.
4. `size-adjust`/`*-override` apply on first paint as well as after swap, so layout metrics are stable across the swap window.

## Integration
- Resolved by `layouts/partials/head/css.html` (`$openDyslexic := resources.Get "css/typeface/OpenDyslexic.css"`) and appended to `$baseFonts`, before the roman/sans/teletype faces, then concatenated into `hugo-brewm.css` and `fingerprint "sha256"`-ed in production.
- With `params.typeface.localHost = false` (config), the theme's `css/typeface-local/OpenDyslexic.css` branch is not taken; this site override is the one that loads.
- CSP: `layouts/partials/analytics.html` sets `font-src 'self' data: https://cdn.jsdelivr.net`. The old GitHub origin is deliberately absent — remote faces would be blocked, so self-hosting is what keeps the OpenDyslexic option functional.
- Font preload in the same partial covers only Atkinson Hyperlegible; OpenDyslexic is left to lazy `@font-face` loading because it is opt-in.
