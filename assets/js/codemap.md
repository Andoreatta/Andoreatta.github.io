# assets/js/
## Responsibility
`notes.js` (325 lines) is the only site JavaScript. It is a dependency-free, `'use strict'` pair of IIFEs that adds notes-page affordances the theme does not ship: heading permalinks, copy buttons, keyboard access to scrollable code, persistent checklists, and the `<IP>`-style placeholder bar. It never runs outside `.notes-article`.

## Design
**Module 1 — notes article (1–138).** Guards on `.notes-article #content` and returns immediately otherwise.
- *Heading anchors* (9–18): appends `<a class="heading-anchor" href="#id">#</a>` to every `h2/h3/h4[id]`; `aria-label="Link to this section"`, `data-pagefind-ignore` so Pagefind does not index the glyph.
- *Copy buttons* (20–78): collects `.highlight` blocks, then bare `pre` not already inside one; inserts `<button class="notes-copy">` (bare `pre` gets a `.notes-code-wrap`). Handler reads `codeElement.innerText` **at click time**, so placeholder-substituted values are what get copied, not the template text. Prefers `navigator.clipboard` when `window.isSecureContext`; otherwise a hidden readonly `<textarea>` + `execCommand('copy')` fallback. Label flips to `copied` for 1.5 s.
- *Keyboard scroll* (80–87): computed `overflow-x: auto|scroll` plus `scrollWidth > clientWidth + 1` → `tabIndex = 0`, making wide code focusable and arrow-scrollable.
- *Checklist persistence* (89–137): `localStorage` key `srl-notes-checklist:<pathname>`; value is a JSON object keyed `task-<hash>` where `<hash>` is a 32-bit FNV-1a of the normalised `<li>` text (`toString(36)`). Content-addressed keys survive insertion/reordering. Legacy `task-<index>` entries are migrated in memory on read and dropped from the object; the rewritten map is persisted on the next checkbox change. Checkboxes get an `aria-label` from the item text (180 chars) and a stable `id`. Every storage call is wrapped in `try/catch`; failures degrade to session-only behaviour.

**Module 2 — placeholder bar (140–325).** Guards on `.ph-vars`, which `ph-vars.html` renders only when a page sets `phVars = true`.
- Names are whitelisted in `NAMES` (`IP, ATTACKER, LPORT, DOMAIN, DC, USER, PASS, WORDLIST, DIRLIST, VHOSTLIST, USERS, PORTS`); `TOKEN` is built from that list.
- Chroma can split `\<ATTACKER>\share` across spans, so `findMatch` walks text nodes with a `TreeWalker`, concatenates them, locates a token, and `Range.extractContents()` + `insertNode()` wraps it in a single `.ph` span carrying `data-ph` and `data-orig` (the original `<NAME>`). A 5,000-iteration guard prevents pathological loops.
- `apply()` writes `span.textContent` only — **never `innerHTML`** — using the trimmed input value or `data-orig` when empty.
- `save()` writes `sessionStorage['srl-ph-vars']` as JSON, skipping empty fields **and skipping `PASS` entirely**; `load()` likewise refuses to restore `PASS`. Clear (`[data-ph-clear]`) blanks inputs, removes the key, re-applies. `submit` is `preventDefault()`ed: no network, no navigation.

## Flow
1. `notes.js` is loaded with `defer` from the notes page head block; it executes after HTML parsing and before `DOMContentLoaded` listeners, in file order.
2. IIFE 1 runs: anchor links → copy buttons → keyboard scroll → checklist restore/handlers.
3. `ph-vars.html` has already rendered the form above `#content`, so IIFE 2 finds `.ph-vars` and its `input[data-ph]` map immediately.
4. IIFE 2 wraps every `<TOKEN>` inside `.notes-article .content pre` into `.ph` spans, then `load()` + `apply()` fill them from `sessionStorage`.
5. On later `input` events the form calls `apply()` then `save()`: code blocks update live, storage stays in sync. Copy buttons pick up the filled text because they read `innerText` at click time.

## Integration
- `layouts/notes/single.html`: `{{ block "head" }}` does `resources.Get "js/notes.js" | minify | fingerprint` and emits a deferred script with `integrity`/`crossorigin`; `{{ if .Params.phVars }}` renders `partials/notes/ph-vars.html`.
- `partials/notes/ph-vars.html` supplies the DOM contract: `.ph-vars`, `input[data-ph="NAME"]`, `[data-ph-clear]`, password field with `autocomplete="new-password"`.
- Styling lives in `assets/css/custom.css` (`.notes-copy`, `.heading-anchor`, `.notes-code-wrap`, `.ph-vars*`, `.ph`, checklist amber). Pagefind ignores injected UI via `data-pagefind-ignore`.
- CSP `script-src 'self'` covers the script; storage access is same-origin only and no request is ever made.
