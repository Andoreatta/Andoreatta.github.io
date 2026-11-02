# config/_default/

## Responsibility

Declares the complete Hugo configuration for the bilingual, dark-only site: global build flags, the two languages and their URL trees, output formats, taxonomies, related-content scoring, menus, and the `params` tree that drives theme behaviour. Hugo deep-merges these files over `themes/hugo-brewm/config.toml` (which only pins `module.hugoVersion`), so the values here are the site's authoritative overrides; template `or … "fallback"` expressions are what remains when a key is absent.

## Design

- **Config merge.** `hugo.toml`, `languages.toml` and the two `menus.<lang>.toml` files are loaded from the directory and merged; `menus.<lang>.toml` is the only language-suffixed split.
- **Multilingual URLs.** `defaultContentLanguage = 'en'` plus `defaultContentLanguageInSubdir = false` keeps English at `/` and Portuguese at `/pt-br/`. Each language sets `contentDir`, `locale`, `direction`, `label`; `pt-br.params.description` overrides the site description only for that language.
- **Pagination.** Both languages set `pagination.disableAliases = true` — `/page/1/` aliases duplicated the list URL and produced 127 crawlable soft redirects — and `pagerSize = 8`, `path = 'page'`.
- **Output formats.** `home = ['html', 'rss']`, `taxonomy = ['html']`, `term = ['html']`. `json` was removed because only the unused network-graph aside consumed it, removing a public data dump from every build; taxonomy RSS was dropped because per-term feeds generated ~16 MB of full-content XML.
- **Sitemap policy.** No global `[sitemap] changefreq`: search engines ignore it and it falsely claimed monthly changes. `lastmod` comes from `enableGitInfo`; per-section `[sitemap] changeFreq` lives in content front matter. `enableRobotsTXT = true` generates the crawler file, and `ignoreFiles` keeps scratch/backup files out of the build.
- **Taxonomies and related.** Only `category = 'categories'` and `tag = 'tags'` are wired (no theme `series`/`stage`/`author`), so author metadata falls back to `params.author.name`. Related notes score by shared tags with `threshold = 20`, `includeNewer`, `toLower`, `tags` weight `100`.
- **Markup and security.** `markup.goldmark.renderer.unsafe = true` is required for `<details>`/`<figure>` and the custom shortcodes; CI compensates by scanning content for `<script>`/`<iframe>`/`on*=`/`javascript:` and rejecting shortcodes outside `hint`, `lain-hero`, `running-lain`, `ph-vars`. `canonifyURLs = false` keeps previews relative and prevents `/pt-br/` links resolving against the English root. Passthrough math keeps `$$`, `equation`, `align` and inline `\(` but deliberately excludes `$` because the pentesting notes contain shell variables like `$TARGET`/`$IP`.
- **Typeface.** `params.typeface.webSafe = true` loads only `websafe.css`; `roman`, `sans` and `localHost` are inert and kept only for theme compatibility. `minimalUI = true` swaps the 29 KB base64 `icon.css` for the 12 KB `icon-minimal.css`. Self-hosted Atkinson Hyperlegible and the native mono stack are declared in `assets/css/custom.css`.
- **Dark-only palette.** `params.style.light` and `params.style.dark` (plus their `less`/`more` contrast variants) are intentionally identical near-black/tan/pink values, so `prefers-color-scheme` cannot produce a light page.
- **Analytics hook.** `params.analytics.append = 'head'` makes the theme baseof render the site's `analytics.html` inside `<head>`; the file is used for CSP, `theme-color`, font preload and the language redirect, not analytics.
- **Menus.** English `main` has Posts/Notes/About; Portuguese omits Notes and keeps Posts/About. Both `footer` menus link LinkedIn and GitHub, with `pre` selecting the footer icon.

## Flow

- Hugo merges the directory, then templates read `site.Params.*` and `site.Language.*`. Language tables drive `content/en` → `/` and `content/pt-br` → `/pt-br/`; `absLangURL`/`relLangURL` and `translationKey` pair pages, and `.IsTranslated` drives hreflang.
- `params.analytics.append` is read in `themes/hugo-brewm/layouts/_default/baseof.html`, which calls `layouts/partials/analytics.html` (CSP meta, `theme-color`, font preload, `pt-br` redirect).
- `params.typeface`, `search`, `logo`, `posts` and `style` feed `layouts/partials/head/css.html` and, via `resources.ExecuteAsTemplate`, `themes/hugo-brewm/assets/css/layout/_default/baseof.css` and `assets/js/accessibility.js`.
- `AllowAIRobots` → `layouts/robots.txt`; sitemap filters → `layouts/_default/sitemap.xml`; `socialCard`/`extMeta`/`favicon`/`author` → `layouts/partials/head/meta.html`; `search.enable`/`pagefind` → theme `partials/search.html` and `layouts/partials/search/pagefind.html`; `RSS.limit`/`content` → theme `_default/rss.xml`; `home.*`/`posts.*` → theme `list.html`/`single.html`; menus → theme `partials/menu.html` and `layouts/partials/footer.html`.
- `related` is consumed by `site.RegularPages.Related` in `layouts/partials/notes/related.html` and the OpenGraph `og:see_also` block of `layouts/partials/head/meta.html`.

## Integration

- **Content front matter:** `translationKey`, `type`, `tags`, `categories`, `[sitemap] changeFreq`, `noIndent`, `toc`, `weight` are read by layouts and must match the language/taxonomy/sitemap policy set here.
- **Theme defaults overridden:** the theme provides only `module.hugoVersion`; the site replaces `head/css.html`, `head/js.html`, `head/meta.html`, `analytics.html`, `footer.html`, `robots.txt` and `sitemap.xml`, so config keys must stay compatible with those overrides.
- **CI:** `.github/workflows/hugo.yml` pins Hugo 0.169.0 extended, sets `HUGO_ENVIRONMENT`/`HUGO_ENV=production`, checks out with `fetch-depth: 0` so `enableGitInfo` can supply `lastmod`, and enforces the unsafe-HTML/shortcode allowlist that `unsafe = true` makes necessary.
- **i18n:** `enableMissingTranslationPlaceholders = false` works with `i18n/pt-br.toml`, which supplies the 13 keys absent from the theme's `pt_br` catalogue.
