# Cyber Essentials readiness evidence downloads

The authenticated `/ce-readiness` page offers the existing CSV and a dated
customer PDF via `/ce-readiness.pdf`. Both downloads are read-only and available
to the same portal roles as the page, including the allowlisted read-only
service identity. The platform remains responsible for authorisation and
evidence; the portal adds no scoring, control mapping or certification verdict.

`GET /ce-readiness.pdf` proxies `GET /v1/portal/ce-readiness?format=pdf`, forwarding
the verified Cloudflare Access JWT verbatim. The upstream path and format are
fixed. Customer query parameters, including tenant hints and alternate formats,
are never propagated. Tenant scope is resolved by the platform from the verified
identity. Existing JSON page reads and CSV requests retain their contracts.

The platform generates the PDF from its existing tenant read model without
retaining a report or writing to the database. The pack carries generation time,
thresholds, count-only estate evidence and freshness, per-device reporting and
update evidence, outstanding critical/high items and existing control evidence.
Unknown, stale, silent, partial and not-evidenced values remain explicit. Due
dates retain the conservative advisory-publication-plus-14-days basis.

The proxy streams bytes unchanged and preserves the platform's `Content-Type`,
`Content-Disposition` and numeric `Content-Length`. The shared download helper
closes the upstream response after completion or interruption. The PDF response
uses `Cache-Control: private, no-store` for customer evidence. Upstream refusals
before streaming use the existing HTML error pages without attachment headers;
an interrupted transfer raises and retains the length guard against a silently
successful truncated file. PDF layout and evidence computation belong to the
platform contract, `contracts/portal-api.md`.

Regression coverage: `tests/test_pat2364_ce_readiness_pdf.py` checks the link,
role parity, JWT and fixed request scope, byte/header preservation, response
closure, invalid identities, upstream refusals and interrupted transfers using
synthetic data. The download suite covers compression handling across the local
HTTP stub. A read-only synthetic page walk uses
`python e2e/walk/walk.py --routes /ce-readiness`.
