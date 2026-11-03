# Patched.im — Documentation site (`docs.patched.im`)

Customer-facing documentation surface for **Patched**. Plain static HTML / CSS,
no build step, no framework. Served as a Cloudflare Worker static-assets project,
separate from the marketing site so `docs.patched.im` resolves to the docs landing
rather than the marketing homepage.

Stood up for **PAT-294** after a client reached an unresolved `docs.patched.im`.

```
patched-im-docs/
├── index.html      # landing + guide index
├── _redirects      # compatibility redirects for retired legacy guides
├── styles.css      # self-contained; design tokens kept in sync with patched.im
├── favicon.*       # canonical Brand v3 geometric P assets
└── wrangler.jsonc  # Worker name + docs.patched.im Custom Domain binding
```

The vNext documentation covers collector deployment, endpoint evidence,
configuration assurance, reports, external remediation, the customer portal,
security and privacy. Package requests, scheduled patch deployment, installer
verification and antivirus exclusions for the legacy updater are retired. The
old URLs redirect to the closest retained guide.

## Run it locally

```bash
python3 -m http.server 8000   # then visit http://localhost:8000
```

## Deployment

`.github/workflows/deploy-docs.yml` validates every pull request and deploys
every push to `main` to Cloudflare Workers Static Assets. It is the authoritative
publication path for `docs.patched.im`; GitHub Pages and the `patched.im` repo
do not publish this hostname.

The workflow requires these GitHub Actions settings, neither of which belongs in
the repository:

- `CLOUDFLARE_API_TOKEN` secret with least-privilege access to deploy the existing
  `patched-im-docs` Worker.
- `CLOUDFLARE_ACCOUNT_ID` Actions variable for the account that owns that Worker.

A note on the token, because this failed once in a way that looked like the
workflow itself was broken: the first push-triggered run (2026-08-11, run
31478140926) failed with Cloudflare `Authentication error [code: 10000]`
because the API token did not yet carry the permissions the deploy needs.
Only the token's Cloudflare-side permissions were at fault, not the workflow
or the secret, so nothing in this repository changed to fix it and no commit
records the repair. If a deploy starts failing on code 10000 again, check the
token's permissions at https://dash.cloudflare.com/profile/api-tokens before
looking anywhere else.

Manual fallback, from an up-to-date `main` checkout with authenticated Wrangler:

```bash
npx wrangler deploy
```

The `routes` entry in `wrangler.jsonc` registers `docs.patched.im` as a **Custom
Domain**, which makes Cloudflare provision the DNS record and edge certificate
automatically. If the deploying token lacks zone DNS-edit permission, add the
Custom Domain once in the Cloudflare dashboard
(Workers & Pages → patched-im-docs → Settings → Domains & Routes → Add Custom
Domain → `docs.patched.im`); subsequent `wrangler deploy` runs then just push
content.

## Brand

The site consumes canonical Brand Kit v3.0.0: Inter for public-facing type, the
blue/navy system, and the geometric open-centre P lockups and icons. JetBrains
Mono is restricted to literal code and technical values inside guides. When the
kit changes, vendor the versioned `Patched-LTD/branding` release instead of
recreating its assets locally.
