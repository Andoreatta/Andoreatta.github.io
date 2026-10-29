# srl.exp.net

Static bilingual blog built with [Hugo](https://gohugo.io/) and the
[hugo-brewm](https://github.com/foxihd/hugo-brewm) theme.

- English: `/`
- Portuguese (Brazil): `/pt-br/`
- Canonical domain (future): `https://serial.experiments.network/`
- Current deployment: `https://andoreatta.github.io/`

The theme is tracked as a Git submodule at `themes/hugo-brewm`.

## Local development

Hugo extended 0.168.0 or newer is required.

```sh
git submodule update --init --recursive
hugo server --minify --gc
```

Open the URL printed by Hugo, usually `http://localhost:1313/`.

With search enabled, Pagefind is only generated during a production build:

```sh
hugo --gc --minify
npx pagefind --site public
```

## Writing

English content lives in `content/en/`; Portuguese content lives in
`content/pt-br/`. Posts must use `type = 'post'` in their front matter.

Create a post in one language:

```sh
hugo new content en/posts/my-post.md
hugo new content pt-br/posts/meu-post.md
```

Use the same `translationKey` in both files so the language switcher and the
Portuguese-browser redirect can find the translated version.

## Language routing

`layouts/partials/analytics.html` contains a small, self-contained script that:

1. Redirects a first-time visitor on an English page to the matching
   Portuguese page when the browser advertises a `pt` language.
2. Does nothing on Portuguese pages.
3. Remembers a manual language choice in `localStorage`, so choosing English
   does not redirect the reader back to Portuguese.

If JavaScript is disabled, the site stays in English and the theme's language
switcher remains available.

## Typography

[Atkinson Hyperlegible](https://www.brailleinstitute.org/freefont) is
self-hosted under `static/fonts/atkinson-hyperlegible/` and loaded through
`assets/css/custom.css`. The font is licensed under the SIL Open Font License
1.1; see `static/fonts/atkinson-hyperlegible/OFL.txt`.

## Deployment

Pushes to `main` trigger `.github/workflows/hugo.yml`, which builds the site,
runs Pagefind, and deploys to GitHub Pages using GitHub Actions.

The repository is a GitHub user site, so Pages must use:

- **Settings → Pages → Build and deployment → Source:** GitHub Actions

## Attaching the custom domain

When DNS is ready:

1. Add a file named `static/CNAME` containing:

   ```text
   serial.experiments.network
   ```

2. Change `baseURL` in `config/_default/hugo.toml` to:

   ```toml
   baseURL = 'https://serial.experiments.network/'
   ```

   Also update `params.socialCard.images` to the same domain.

3. Create a DNS record:

   ```text
   CNAME  serial  andoreatta.github.io
   ```

4. In GitHub, set the custom domain under **Settings → Pages**.
5. Wait for DNS and the certificate, then enable **Enforce HTTPS**.

## Updating the theme

```sh
git submodule update --remote --merge themes/hugo-brewm
git add themes/hugo-brewm
git commit -m "Update hugo-brewm theme"
```
