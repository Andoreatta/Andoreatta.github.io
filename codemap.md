# srl.exp.net — repository atlas

## Purpose

Bilingual personal site: blog posts plus a large penetration-testing field manual.
English is served from `/`, Brazilian Portuguese from `/pt-br/`. The output is
fully static (no backend, no runtime config, no cookies) and is deployed to
GitHub Pages at `https://serial.experiments.network/` (`static/CNAME`).

Scale: 84 note articles + 12 note section indexes (English only), 1 post per
language, 2 taxonomies. Search is a build-time Pagefind index.

## Stack

| Component | Version / source |
|---|---|
| Hugo | 0.169.0 extended, pinned in `.github/workflows/hugo.yml` and checksum-verified |
| Theme | `hugo-brewm` v2.11.1 as a git submodule (`themes/hugo-brewm`), site overrides in `layouts/` |
| Search | Pagefind 1.5.2 (`package.json`, lockfile, invoked from `node_modules/.bin`) |
| Runtime JS | none beyond `assets/js/notes.js` and the theme bundle |
| CSS | Hugo Pipes: concat → `ExecuteAsTemplate` → minify → fingerprint |
| CI | GitHub Actions → Pages (OIDC), Dependabot for actions/npm/submodule |

## Entry points

- **Build behaviour** — `config/_default/hugo.toml` (+ `languages.toml`, `menus.<lang>.toml`).
- **Document skeleton** — `themes/hugo-brewm/layouts/_default/baseof.html`; site fills the `head` / `main` / `exclude` blocks.
- **Home page** — `content/en/_index.md` (`{{< lain-hero >}}`) and `content/pt-br/_index.md`.
- **Notes** — `content/en/notes/**` rendered by `layouts/notes/{single,list}.html`.
- **Deploy** — `.github/workflows/hugo.yml`.

## Repository directory map

| Directory | Responsibility | Map |
|---|---|---|
| `config/` | Hugo config root (router) | [config/codemap.md](config/codemap.md) |
| `config/_default/` | Languages, outputs, taxonomies, params, menus | [config/_default/codemap.md](config/_default/codemap.md) |
| `i18n/` | Delta `pt-br` catalogue (13 entries the theme lacks) | [i18n/.codemap.md](i18n/.codemap.md) |
| `layouts/` | Template root; site files shadow theme files wholesale | [layouts/.codemap.md](layouts/.codemap.md) |
| `layouts/_default/` | `single.html` override + sitemap policy | [layouts/_default/.codemap.md](layouts/_default/.codemap.md) |
| `layouts/notes/` | Notes section templates (single + list) | [layouts/notes/.codemap.md](layouts/notes/.codemap.md) |
| `layouts/shortcodes/` | `hint`, `lain-hero` | [layouts/shortcodes/.codemap.md](layouts/shortcodes/.codemap.md) |
| `layouts/partials/` | `analytics.html` (CSP/language), footer, running-lain | [layouts/partials/.codemap.md](layouts/partials/.codemap.md) |
| `layouts/partials/head/` | Vendored `meta.html`, `css.html`, `js.html` overrides | [layouts/partials/head/.codemap.md](layouts/partials/head/.codemap.md) |
| `layouts/partials/notes/` | Nav tree, cards, related, prev/next, placeholder form | [layouts/partials/notes/.codemap.md](layouts/partials/notes/.codemap.md) |
| `layouts/partials/search/` | Lazy Pagefind UI loader | [layouts/partials/search/.codemap.md](layouts/partials/search/.codemap.md) |
| `layouts/partials/ascii/` | Braille portrait partial | [layouts/partials/ascii/.codemap.md](layouts/partials/ascii/.codemap.md) |
| `assets/` | Hugo Pipes source root; shadows theme assets by path | [assets/codemap.md](assets/codemap.md) |
| `assets/css/` | `custom.css` terminal/editorial layer | [assets/css/codemap.md](assets/css/codemap.md) |
| `assets/css/typeface/` | Self-hosted OpenDyslexic override | [assets/css/typeface/codemap.md](assets/css/typeface/codemap.md) |
| `assets/js/` | `notes.js` (anchors, copy, checklists, placeholders) | [assets/js/codemap.md](assets/js/codemap.md) |
| `.github/` | Build, Pagefind, sitemap validation, deploy, dependency policy | [.github/codemap.md](.github/codemap.md) |

Not mapped: `content/` (Markdown corpus), `static/` (fonts, images, CNAME),
`themes/` (vendored theme), `public/` and `resources/` (build output, ignored).

## Request flow

1. Hugo resolves the template: `layouts/<section>/<kind>.<ext>` → `layouts/_default/<kind>.<ext>` → theme equivalent.
2. `baseof.html` renders `<head>`: `head.html` → `head/meta.html` (canonical, hreflang, OG/Twitter, JSON-LD) → `partialCached "head/js.html"` → `partialCached "head/css.html"` → `analytics.html` (CSP, referrer, font preload, language redirect).
3. Body: `header.html` → `main` block (page template) → `exclude` block (related/colophon) → `footer.html`.
4. Assets are resolved through Hugo Pipes; production filenames are content-hashed and carry SRI.

## Build flow

`content/**/*.md` → Goldmark (`unsafe = true`, passthrough math) → templates →
`hugo --gc --minify` → `public/` → Pagefind index → sitemap XML validation →
Pages artifact → deploy.

CI additionally runs a content gate before the build (rejects active HTML and
non-allowlisted shortcodes) and pins Hugo/Pagefind.

## Content model

- **Notes** — `type = "notes"`, English only. Front matter: `title`, `description`
  (120–155 chars, required by convention), `date`, `weight` (nav order), `tags`,
  optional `phVars` (placeholder form) and `task` (interactive checkboxes).
  Pagefind indexes `article[data-pagefind-body]`; injected UI is ignored.
- **Posts** — `type = "post"`, paired EN/PT via `translationKey`; colophon loads
  `qrcode.js` only on these pages.
- **Taxonomies** — `tags`, `categories`. Tag terms with fewer than three notes
  are `noindex, follow` and excluded from the sitemap (threshold duplicated in
  `head/meta.html` and `_default/sitemap.xml`).
- **Translations** — only posts/about/home are paired; hreflang clusters are
  emitted only when `.IsTranslated`.

## Invariants and gotchas

1. **Overrides replace, never merge.** A site file at the same path as a theme
   file wins wholesale; no `super`/partial inheritance.
2. **`layouts/` and `i18n/` maps are dot-prefixed.** Hugo parses *every* file in
   those trees as a template/translation, so their codemaps are `.codemap.md`.
   Other directories use `codemap.md`.
3. **Paginator contract.** `partial "paginator.html"` memoises `.Paginate`;
   every caller must pass the same page/arguments. `head/meta.html` reuses it for
   paginated term canonicals and titles.
4. **CSP needs `'unsafe-inline'`.** The theme's `accessibility.js` injects
   `onclick` handlers and `<style>` at runtime, so hashes cannot replace it.
5. **`unsafe = true` is load-bearing** for `<details>`/`<figure>`/`<mark>` in
   content; the CI gate is the compensating control. Update its shortcode
   allowlist when adding a shortcode.
6. **Pagefind scoping.** Only `data-pagefind-body` regions are indexed; nav,
   cards, related lists, copy buttons and the braille portrait are excluded.
7. **Fingerprint + SRI must come from the same resource object**, or a cached
   stylesheet can outlive its hash after a deploy.
8. **GitHub Pages sets no security headers.** HSTS, `nosniff` and
   `frame-ancestors` require a proxy; the site ships meta CSP + referrer only.
9. **Notes are English-only by design.** A `/pt-br/` URL exists only for pages
   with a `translationKey` counterpart.

## Common tasks

- **Add a note** — create `content/en/notes/<section>/<slug>.md` with `type = "notes"`,
  a description, `weight`, and tags. Nav order follows `weight`; related links
  follow shared tags.
- **Add a post** — `content/en/posts/<slug>.md` plus a `pt-br` counterpart sharing
  `translationKey`.
- **Change SEO** — `layouts/partials/head/meta.html`; sitemap policy in
  `layouts/_default/sitemap.xml`.
- **Change build/deploy** — `config/_default/` + `.github/workflows/hugo.yml`.
- **Rebuild search** — `hugo --gc --minify && ./node_modules/.bin/pagefind --site ./public`.
- **Preview** — `hugo server -D` (no Pagefind index unless you run it separately).
