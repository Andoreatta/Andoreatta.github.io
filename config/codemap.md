# config/

## Responsibility

Single entry point for Hugo build configuration. Everything the site build needs — base URL, languages, output formats, markup, taxonomies, menus and all `params` — is declared in `config/_default/`; Hugo merges those files over the theme before any template runs. No other directory in the repo changes build behaviour, and templates only read the resulting `site.*`, `site.Params` and `site.Language` values.

## Design

- **Directory-based config merge.** Hugo loads every TOML file under `config/_default/` and deep-merges them, with `hugo.toml` holding global keys and `menus.<lang>.toml` holding one menu set per language. There is no environment-specific `config/production/`; CI instead sets `HUGO_ENVIRONMENT`/`HUGO_ENV`.
- **Language-suffixed files.** `menus.en.toml` and `menus.pt-br.toml` exist separately because Hugo resolves the `<name>.<lang>.toml` suffix to the matching language, not because the site keeps duplicated global config.
- **No theme config directory.** The theme ships only `themes/hugo-brewm/config.toml`, which declares `module.hugoVersion` (`min = "0.135.0"`, `extended = false`). Every site key is therefore an override of a template-level `or … "fallback"` default, not of a theme TOML block.
- **No environment overlays.** There is no `config/production/` or `config/development/`; local and CI builds read the same files, and the only production-specific input is the `HUGO_ENVIRONMENT`/`HUGO_ENV` pair exported by the workflow.
- **One level of detail.** This file is a router only; the key-by-key rationale and the template consumers are documented in `config/_default/codemap.md`.

## Flow

`config/_default/*.toml` → Hugo config merge (site over theme) → `site.*` / `site.Params` / `site.Language` → `layouts/` and `themes/hugo-brewm/layouts/` at render time. The only writer of this tree is the build step `hugo --gc --minify` in `.github/workflows/hugo.yml`; nothing at runtime mutates it.
The merge is deterministic and read-only: templates may read values but never write them back, so a misconfiguration surfaces as a build error or a fallback, not as runtime state.

## Integration

- **Upward:** consumed by every layout/partial, especially `layouts/partials/head/*`, `layouts/robots.txt`, `layouts/_default/sitemap.xml` and the theme's `_default/baseof.html`, `list.html`, `single.html`, `rss.xml`.
- **Sideways:** `i18n/` supplies the `pt-br` strings, `content/` supplies front matter (`translationKey`, `type`, `tags`, `[sitemap] changeFreq`), and `.github/workflows/hugo.yml` pins Hugo 0.169.0 and the production environment.
- **Downward:** follow `config/_default/codemap.md` for the actual keys; do not duplicate or restate them here.
- **Ownership:** this tree is the only place to change build-level behaviour; template overrides in `layouts/` assume the keys documented below exist with the values set here.
