# assets/
## Responsibility
Hugo Pipes source root for the site. Files here are build inputs, not published as-is: Hugo reads them, concatenates/minifies/fingerprints, and emits hashed bundles under the site root. The tree contains only site overrides — `css/custom.css`, `css/typeface/OpenDyslexic.css`, `js/notes.js` — plus this codemap. Every other `resources.Get` path falls through to `themes/hugo-brewm/assets/`.

## Design
- **Shadowing by path.** Hugo's asset union searches the project `assets/` before the theme's, so a file at the same relative path replaces the theme file for every `resources.Get`. `css/custom.css` therefore replaces the theme's three-line stub, and `css/typeface/OpenDyslexic.css` replaces the remote-font version. Unshadowed theme assets (`css/root.css`, `css/component/*`, `css/layout/*`, `js/default.js`, …) still load.
- **Two bundles + two standalone resources.** One CSS bundle (`hugo-brewm.css`) and one JS bundle (`hugo-brewm.js`) per page; `css/media/print.css` and `js/notes.js` are emitted separately so they can be scoped to print / notes pages.
- **CSS order is API.** Base layout and typesetting → components → font faces → conditional extras → `custom.css` last. Later files win ties, which is why site overrides need no `!important`.
- Only `css/custom.css` and `js/notes.js` are hand-maintained site code; everything else is theme code addressed by path.

## Flow
1. `resources.Get "css/…"` / `"js/…"` — resolves project asset first, theme asset second.
2. `resources.Concat` — builds `"hugo-brewm.css"` / `"hugo-brewm.js"` from the slice order defined in the head partials.
3. `resources.ExecuteAsTemplate` — required because theme `css/layout/_default/baseof.css` interpolates `site.Params.style` palette values with `{{ }}`; the whole concatenated bundle is rendered as a Go template.
4. `minify`.
5. Production only: `fingerprint "sha256"` → content-addressed filename.
6. Template emits `RelPermalink`, `Data.Integrity`, and `crossorigin="anonymous"` on `<link>`/`<script>`. Development skips steps 5–6 and serves the unhashed URL without SRI.

`js/notes.js` bypasses `Concat`: `resources.Get | minify | fingerprint` in `layouts/notes/single.html`, so notes pages fetch one extra deferred script.

## Integration
- `layouts/partials/head/css.html` (site override of the theme partial) assembles and fingerprints the CSS bundle; `layouts/partials/head/js.html` does the same for JS. Both are called by `themes/hugo-brewm/layouts/partials/head.html`, included from `themes/hugo-brewm/layouts/_default/baseof.html`.
- `layouts/partials/head/css.html` also defines `partials/head/css/inline.html` (per-page fallback/inline CSS) and emits `css/media/print.css` as a separate `media="print"` link.
- `layouts/notes/single.html` loads `js/notes.js` in its `{{ block "head" }}` and conditionally renders `partials/notes/ph-vars.html`.
- `layouts/partials/analytics.html` carries the CSP these same-origin bundles rely on (`script-src 'self'`, `style-src 'self'`, `font-src 'self'`) and preloads the Atkinson Hyperlegible face.
- Build is plain `hugo --gc --minify` (no npm scripts); Get/Concat/ExecuteAsTemplate/minify/fingerprint all happen inside the build — there is no external bundler or post-processing step.
