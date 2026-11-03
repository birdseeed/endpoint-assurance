# Security

This is archived code from a service that was retired in October 2026 and whose infrastructure has been decommissioned. It is not maintained, so please do not deploy it or install its agents.

Before publishing, the code and its history were scanned for secrets. The only matches are test fixtures and placeholder values, and server addresses, hostnames and tokens in the documentation have been replaced with documentation placeholders.

On 1 and 2 November 2026 I fixed a number of authentication and hardening issues found during a final review, including removing body only HMAC signatures for agent requests so a captured request cannot be replayed, and binding dashboard sessions to a verified Cloudflare Access token rather than trusting an email header. The detailed working notes and test results from that review are in [docs/archive](docs/archive).

If you spot something, I would genuinely like to hear about it; please open an issue without including any credentials or personal data.
