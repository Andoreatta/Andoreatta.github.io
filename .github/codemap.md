# .github/
## Responsibility
CI/CD and dependency policy for the site. The only pipeline is `.github/workflows/hugo.yml`, which builds the Hugo output, indexes it with Pagefind, validates the sitemaps, and deploys to GitHub Pages. `.github/dependabot.yml` keeps actions, npm tooling, and the theme submodule current.

## Design
- **Single workflow, two jobs.** `build` produces the artifact; `deploy` publishes it through the `github-pages` environment. `concurrency.group: pages` serialises deployments (`cancel-in-progress: false`).
- **Least privilege per job.** `build` has `contents: read` only; `deploy` has `pages: write` + `id-token: write` (OIDC for Pages). No workflow-level permissions.
- **Supply-chain pinning.** Actions are pinned by full commit SHA with a version comment (`checkout` v7.0.1, `configure-pages` v6.0.0, `upload-pages-artifact` v5.0.0, `deploy-pages` v5.0.1). Hugo is a pinned `.deb` (`HUGO_VERSION`), verified twice: against a hash embedded in the workflow and against the release's `hugo_<ver>_checksums.txt`. `persist-credentials: false` keeps the token out of `.git/config`.
- **Reproducible tooling.** `npm ci --ignore-scripts` installs Pagefind from `package-lock.json`; the binary is invoked as `./node_modules/.bin/pagefind` instead of `npx`, so a build cannot silently change indexer version.
- **Content gate.** A dependency-free Python step runs before the build and rejects active HTML (`<script>`, `<iframe>`, `<object>`, `<embed>`, `<base>`, `on*=`, `javascript:`) and shortcodes outside `{hint, lain-hero, running-lain, ph-vars}` after blanking fenced and inline code. This compensates for `markup.goldmark.renderer.unsafe = true`.
- **Dependabot** runs weekly for `github-actions`, `npm`, and `gitsubmodule`; minor/patch updates are grouped.

## Flow
`push` to `main` (or manual dispatch) → install Hugo (download, checksum, dpkg) → checkout with submodules and full history (`enableGitInfo` needs `fetch-depth: 0`) → `npm ci` → content gate → `hugo --gc --minify` → Pagefind index over `public/` plus removal of unused UI bundles → sitemap XML parse check → `upload-pages-artifact` → `deploy-pages`.

## Integration
- Consumes `config/_default/hugo.toml` (`enableGitInfo`, outputs, baseURL), `package.json`/`package-lock.json`, the `themes/hugo-brewm` submodule pointer, and `content/**/*.md` (gate).
- Produces `public/` (uploaded artifact) and the live site at `https://serial.experiments.network/` (`static/CNAME`).
- The gate's shortcode allowlist must be updated whenever a new shortcode is added under `layouts/shortcodes/`.
