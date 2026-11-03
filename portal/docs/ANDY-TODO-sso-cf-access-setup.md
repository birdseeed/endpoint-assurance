# Andy TODO — wire up Microsoft + Google SSO for the customer portal (PAT-127)

This is the manual, credential-holding half of PAT-127. Everything code/schema-side
(tenant-config fields, domain -> tenant auto-binding, manual override, docs) is done
in this PR and in `Patched-LTD/patched.im` PR for PAT-127. **None of the steps below
were run by the agent that wrote this** — they all need your own Entra tenant admin,
Google Workspace/Cloud console access, and Cloudflare Zero Trust admin.

**Target surface: `app.patched.im` (the customer portal, this repo), NOT
`dashboard.patched.im`.** The internal staff dashboard already has its own,
separate Entra SSO (PAT-460, done) and is out of scope here — don't reuse or
touch that Access application.

## 1. Register an Entra (Azure AD) app for Cloudflare Access

In the Microsoft Entra admin center (your Patched.im tenant, or a tenant you
designate as the SSO broker — see note below):

1. **App registrations -> New registration.** Name: `Patched Portal (Cloudflare Access)`.
2. Redirect URI (Web): `https://<your-team>.cloudflareaccess.com/cdn-cgi/access/callback`
   (the exact value is shown when you add the IdP in Cloudflare in step 3 — do
   that step first if you want to copy-paste it rather than predict it).
3. **Certificates & secrets -> New client secret.** Copy the value immediately
   (Entra only ever shows this once).
4. Record: **Application (client) ID**, **Directory (tenant) ID**, **client secret value**.
5. **API permissions**: default `User.Read` (delegated) is enough for basic
   sign-in + email claim. No admin consent needed for that alone.

> **Note on which Entra tenant:** customers are NOT expected to register their
> own app in their own Entra tenant for v1 (that's the heavier BYO-IdP model
> tracked separately in PAT-711, not this ticket). This is a **multi-tenant**
> Entra app registration (any org can sign in), so one registration in
> Patched's own tenant covers every customer's Microsoft users. When
> registering, set **Supported account types** to "Accounts in any
> organizational directory (Any Microsoft Entra ID tenant - Multitenant)".

## 2. Register a Google OAuth client for Cloudflare Access

In Google Cloud Console (a project under Patched's Google Workspace/Cloud org):

1. **APIs & Services -> Credentials -> Create Credentials -> OAuth client ID.**
   Application type: Web application. Name: `Patched Portal (Cloudflare Access)`.
2. Authorized redirect URI: `https://<your-team>.cloudflareaccess.com/cdn-cgi/access/callback`
   (same callback path pattern as Entra, again shown exactly in Cloudflare's
   IdP setup screen).
3. If prompted for an OAuth consent screen: External user type, since any
   Google Workspace or consumer Gmail user may need to sign in (customers are
   SMEs, not all on Workspace).
4. Record: **Client ID**, **Client secret**.

## 3. Add both as identity providers in Cloudflare Zero Trust

Zero Trust dashboard -> **Settings -> Authentication -> Login methods -> Add new**:

1. **Add Azure AD**: paste the Application (client) ID, Directory (tenant) ID,
   and client secret from step 1. Cloudflare will show you the exact redirect
   URI to put back into the Entra app registration if you didn't already.
2. **Add Google**: paste the Client ID and secret from step 2.
3. Leave the existing **One-time PIN** login method in place — it remains the
   fallback for tenants not using SSO (locked decision, PAT-127).

## 4. Configure the CF Access application for `app.patched.im`

**Zero Trust -> Access -> Applications -> `app.patched.im`** (the existing
application — do not create a second one for the same hostname):

1. **Login methods**: enable Azure AD + Google (added in step 3) alongside
   One-time PIN.
2. **Policies** — this is where the two different session lifetimes the
   ticket asks for come from (CF Access supports a distinct session duration
   per **policy**, not per application — see `contracts/portal-api.md` in the
   platform repo for why this needed no application code):
   - **Policy A — "SSO session"**: Include rule = *Login Methods* includes
     Azure AD OR Google. **Session Duration: 8 hours.**
   - **Policy B — "Email PIN session"**: Include rule = *Login Methods*
     includes One-time PIN. **Session Duration:** leave at whatever the
     current weekly value is (unchanged behaviour — do not touch this policy
     beyond confirming its login-method scope).
   - Keep both policies' actual access grant unchanged (whatever email-domain
     Include rules already gate `app.patched.im` today) — you're only adding
     the login-method condition + session duration split, not changing who
     is allowed in.
3. Confirm existing behaviour is undisturbed: a One-time-PIN user should still
   get the same session length as before; only the new Microsoft/Google path
   gets the 8h cap.

## 5. Register each customer tenant's email domain (per tenant, ongoing)

Once the above is live, every **existing and new** tenant needs its email
domain registered so its users' SSO logins auto-resolve without you adding
each person to `portal_users` by hand. One call per tenant (internal listener,
`ADMIN_API_TOKEN`, over Tailscale — same posture as the existing
`/admin/portal-users` calls you already make per PAT-693):

```bash
curl -s -X POST https://example-api-host.example-tailnet.ts.net:8443/admin/tenant-email-domains \
  -H "Authorization: Bearer $ADMIN_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"domain": "customer.example", "tenant_id": "<tenant-uuid>"}'
```

- A domain can only be actively claimed by one tenant — a second POST for a
  domain already claimed elsewhere returns `409`, it will not silently move.
- For a consultant or shared admin address that doesn't belong to the
  tenant's own domain, keep using the existing `/admin/portal-users` explicit
  mapping — it always overrides the domain match.
- This is a natural fit to fold into tenant provisioning (PAT-110) once that
  automation exists; until then it's one extra manual step per new tenant.

## 6. Test before calling it done

- A user at a registered tenant domain, with no existing `portal_users` row,
  can sign in via Microsoft or Google and land on their own tenant's
  overview — never someone else's.
- A user NOT at any registered domain and NOT explicitly mapped gets the
  existing "account not linked to an estate" page (`not_linked.html`), not an
  error.
- The One-time-PIN path still works exactly as it did before this change,
  including its existing (weekly) session length.
- An SSO session actually expires and forces re-auth at 8 hours, not sooner
  or later.

## Explicitly out of scope here (see PAT-711)

Full per-tenant bring-your-own-IdP (each customer connecting their own
Entra/Okta/Google Workspace tenant, `app.patched.im` coming off Cloudflare
Access entirely) is a separate, larger piece of work tracked in PAT-711 — it
supersedes this Cloudflare-Access-with-two-generic-IdPs approach at the point
Patched lands a customer that specifically requires it. Nothing in this PR
forecloses that migration: the domain -> tenant and manual-override
resolution logic is the same shape either way, only the token issuer changes.
