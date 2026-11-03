# Patched Brand Kit v3

**Brand v3** (PAT-2180): the geometric P mark, blue primary, navy and slate
structure, and rationed signal orange. The full identity guidelines are in
`../guidelines/brand-v3.md`. This file covers
what the kit contains and how to consume it.

> **v3.0.0 is a breaking release.** The v2 ring mark (`patched-ring-mark-*`,
> `patched-app-icon*`) is gone from the kit and archived in
> `retired/logo/ring-mark/`. `--accent` is now blue. `--font-display` is now
> Inter. Neutral values moved to a cooler slate ramp. Token *names* from v2
> are kept, so a re-sync restyles consumers rather than breaking their CSS.
> Anything a consumer inlines, such as a copied ring-mark SVG, must be swapped
> by hand. See "Migration" in the guidelines.

## Vendoring the kit

Use `sync-brand.sh` from the root of the `Patched-LTD/branding` repo. Copy that
script into your consuming repo once, then run it whenever you want to pull a new
version:

```sh
# Pin to a specific release tag (recommended for reproducible builds):
REF=brand-v3.0.0 ./sync-brand.sh

# Custom destination:
REF=brand-v3.0.0 ./sync-brand.sh path/to/vendor/brand

# Override the branding repo URL (e.g. HTTPS instead of SSH):
BRAND_REPO=`Patched-LTD/branding.git` REF=brand-v3.0.0 ./sync-brand.sh
```

The script is idempotent — re-running with the same `REF` produces the same
vendored tree.

### Release tags

Releases are tagged in git as `brand-vMAJOR.MINOR.PATCH` (e.g. `brand-v3.0.0`).
The current version is in `kit/VERSION`. Always pin `REF` to a tag in production;
using `main` gives you the latest but may include unreleased changes.

---

## Wiring tokens into an app

```html
<link rel="stylesheet" href="vendor/brand/tokens.css" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" />
```

```css
body { background: var(--surface); color: var(--text-strong); font-family: var(--font-sans); }
a { color: var(--link); }
a:hover { color: var(--link-hover); }
:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: 2px; }
.button-primary { background: var(--primary); color: var(--on-primary); border-radius: var(--radius-sm); }
.button-primary:hover { background: var(--primary-hover); }
.badge-warning { color: var(--warning); background: var(--warning-wash); }
```

- `tokens.json` is the source. `tokens.css` is generated from it and must not be hand-edited.
- Dark mode follows `prefers-color-scheme`. To force a theme, set `data-theme="dark"` or `data-theme="light"` on `<html>`. Put it on `<html>`: the semantic aliases resolve on `:root`.
- Status colours: use `--<status>` for text, `--<status>-solid` for dots, bars and charts, and `--<status>-wash` for backgrounds. Always pair them with a text label.

## Logo files (`logo/`)

| File | Use |
|---|---|
| `patched-mark-primary.svg` | Primary full-colour gradient mark on light surfaces |
| `patched-mark-white.svg` | Reversed mark on navy, dark or blue |
| `patched-mark-navy.svg` | Single-colour navy |
| `patched-mark-mono.svg` | `currentColor` template (menu bar, monochrome) |
| `patched-lockup-horizontal.svg` / `-white.svg` / `-mono.svg` | Horizontal lockup (primary) |
| `patched-lockup-stacked.svg` / `-white.svg` | Stacked lockup |
| `patched-wordmark.svg` / `-white.svg` | Wordmark alone |

In HTML headers, prefer the mark SVG plus live text ("Patched", Inter 700,
-0.02em) so the name stays selectable and accessible.

## Icons (`favicon/`)

| File | Use |
|---|---|
| `favicon.svg` | Scalable favicon, the primary mark. Modern browsers prefer this |
| `favicon.ico` | 16, 32 and 48 px |
| `favicon-16.png` / `favicon-32.png` / `favicon-48.png` | PNG fallbacks |
| `apple-touch-icon.png` | 180 x 180, full-bleed tile (iOS applies the mask) |
| `mask-icon.svg` | Safari pinned tab, single colour |
| `app-icon.svg`, `app-icon-512.png`, `app-icon-1024.png` | App / Dock / store icon: white mark on the brand gradient |
| `profile-400.png` | 400 x 400 circle-safe profile image |

```html
<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48" />
<link rel="icon" href="/favicon.svg" type="image/svg+xml" />
<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
<link rel="mask-icon" href="/mask-icon.svg" color="#2563EB" />
<meta name="theme-color" content="#ffffff" />
```

The social, LinkedIn, X and OG artwork is not vendored. It lives in
`../assets/social` and `../assets/og` for the people running those accounts.

**Email signature (below):** the files still carry v2 styling (signal-orange
web link, posture bar). They are left unchanged in 3.0.0 because the live
transport rule depends on them. Their Brand v3 refresh is a follow-up.

## Email signature

Four files, all email-safe (no `<img>`, no `<style>` block, no `<script>`, no
external URL beyond `mailto:` and `https://patched.im`, inline `style`
attributes only, tables for layout, tags limited to `table`, `tr`, `td`, `a`,
`b`, `strong`, `br`, `div`, `span`, every colour a literal hex — no CSS custom
properties in the output):

| File | Use |
|---|---|
| `email-signature-full.html` | First contact — wordmark, rule, name, role, four contact rows, posture bar, company line. |
| `email-signature-compact.html` | Reply variant — name, role, one contact row (email), company line. No wordmark, no bar. |
| `email-signature.txt` | Plain text fallback. |
| `email-signature-preview.html` | QA harness — both HTML variants and the plain-text variant, rendered on a `--snow` and a `--slate` ground, each with a fake quoted reply above so spacing reads in context. Not itself an email-safe deliverable — it's a browser preview tool and uses a normal `<style>` block. |

Run `./verify-signature.sh` from `kit/` before shipping either HTML file. It
asserts the constraints above mechanically and prints computed WCAG contrast
ratios; see below for the numbers it produces.

### Why there's no image

`brand/brand-digital.jsx`'s `BrandEmailSig` specifies a 64px `AppTile` ring
mark next to the name. That can't ship in a transport-rule signature: a
transport rule can't embed an inline CID image, and Outlook blocks external
images by default — the signature this replaces proves it, rendering a
broken placeholder on every message. Rather than drop the mark and call it a
day, this redesign uses live type for “Patched” so the name remains reliable
without a remote or embedded image. A type-only signature is therefore an
intentional email-safe treatment: the graphic mark cannot travel reliably
through transport rules and mail clients, while the name can.

The `PostureBar` survives, because it's the opposite case: it's rectangles
with background colours, not an image, and Outlook renders background
colours on table cells reliably.

### Font fallback chain

No webfont loads in mail — every font reference is a local stack:

- **Display** (wordmark, name): `Archivo, "Inter Tight", Inter, "Helvetica Neue", Arial, sans-serif`
- **Mono** (role, contact rows, company line): `"JetBrains Mono", "IBM Plex Mono", Consolas, Menlo, monospace`

Outlook desktop (Word rendering engine) has none of the brand fonts
installed on a typical Windows estate, so it lands on Arial for the display
stack and Consolas for the mono stack. That's the intended fallback, not an
accident — both are chosen for being everywhere Word is.

### Deviations from the brand system

Three deliberate departures from `BrandEmailSig` as drawn, each because the
brand-system default doesn't survive email:

**1. Contrast.** `--mute` (#7d8089) and `--signal` (#f5530a) are the brand
system's defaults for the role line and the web link. Both fail WCAG AA for
small text on white. Computed by `verify-signature.sh`:

| Token | Hex | Contrast vs `#ffffff` | AA (4.5:1) |
|---|---|---|---|
| `--mute` (role line, as drawn) | `#7d8089` | 3.95:1 | **FAIL** |
| `--signal` (web link, as drawn) | `#f5530a` | 3.43:1 | **FAIL** |
| `--slate-600` (role line, shipped) | `#5c606a` | 6.29:1 | PASS |
| `--signal-deep` (web link, shipped) | `#c93f04` | 5.00:1 | PASS |
| `--slate` (name, wordmark, email link) | `#0f1115` | 18.90:1 | PASS |

Both substitutes are the next step up the same ramp, per brand convention —
not an off-ramp colour. The company line and the `t`/`m`/`e`/`w` labels have
no colour specified in the original spec table (only the email link and web
link do); they're set in `--slate-600` too, for the same reason and to keep
every text colour in the output passing AA rather than leaving one
unspecified field at the failing `--mute` default.

**2. Dark mode.** No structural cell (wordmark, rule, name, role, contact
rows, company line) carries a `background-color`. That's deliberate: Outlook
and Apple Mail's dark-mode engines invert unset-background text
automatically, so the ink colours above render correctly in both light and
dark without the signature having to detect or branch on theme. The one
exception is the posture bar, which has explicit backgrounds by design (see
above) — and explicit backgrounds are not inverted by client dark-mode
engines, so its colours have to be legible on both grounds *unchanged*.
That rules out `--slate` (#0f1115) for the inactive segment — near-black on
a near-black dark-mode ground disappears. The bar uses `--slate-400`
(#9a9ea7, a mid-grey legible on both `--snow` and `--slate`) for the
inactive segment and `--signal` (#f5530a, invariant across modes per
`tokens.css`) for the active segment.

**3. The posture bar is a device, not a chart.** `BrandEmailSig` renders the
bar at `patched 0.6 / patching 0.07` — real-looking numbers that, stamped on
a person's actual outbound mail, read as a claim about their estate's patch
state. The shipped bar drops the two data-driven proportions and renders one
fixed, small signal-coloured segment (18px) against a longer neutral one
(126px) — no percentage, no legend, nothing that resolves to a number if
someone tried to read it as one. If a reviewer still reads it as a
measurement, drop it entirely rather than caveat it — it hasn't needed to be
dropped so far.

### Placeholders — fill before deploying

| Placeholder | Field | Note |
|---|---|---|
| `XXXXXX` | Landline (`t` row) | The `t` row is a single, self-contained `<tr>` in the contact-rows table — delete that one row if there's no landline to publish; nothing else in the signature depends on it existing. |
| `XXXXXXV` | Company number | Isle of Man company number, six digits + check letter. |
| `XXXXXXXX` | Mobile (`m` row) | **Not specified in the PAT-1627 brief** — the brief names only the landline and company number as placeholders. No real mobile number was supplied to fill this row, so it's left as a placeholder in the same style rather than a fabricated number. Flagged separately in the implementation report; fill or remove the `m` row before deploying. |

### What PAT-1626 (transport rule) needs from this

Two settings, not built here — PAT-1626 is Andy-only and out of scope for
this ticket:

- **Fallback action: Ignore.** If the rule can't apply the signature (e.g.
  message already has HTML that conflicts), skip silently rather than
  blocking mail.
- **Exception: body contains "Registered in the Isle of Man".** Without it,
  a transport rule that appends on every outbound message stacks a fresh
  copy of the signature onto every reply in a thread. That phrase is unique
  to the company line and only ever appears once per message if the
  exception is honoured, so it's the marker to gate on.
