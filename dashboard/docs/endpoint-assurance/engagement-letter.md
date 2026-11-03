> **TEMPLATE - REQUIRES SOLICITOR REVIEW BEFORE USE WITH ANY CUSTOMER.**
> This document is a drafting starting point, not a finished contract and not
> legal advice. It has not been reviewed by a qualified solicitor. Every
> `[LEGAL: ...]` placeholder marks a commercially or legally load-bearing
> value - a liability cap, a governing law, a notice period, a retention
> period, an insurance requirement - that has been deliberately left unset
> rather than filled with a plausible-looking number. These are decisions
> for Andy to make with proper advice, not defaults to accept because they
> are already typed in. Do not send this letter to a customer, and do not
> let a specialist fill in a placeholder from guesswork, until every
> `[LEGAL: ...]` marker below has been replaced with a reviewed, decided
> value and this warning block has been removed.
>
> **Template - PAT-1300.** For the specialist preparing an engagement: fill
> every `[CUSTOMER NAME]`-style bracket from the signed scoping questionnaire
> (`scoping-questionnaire.md`) and the agreed order, and delete this
> paragraph and the warning above before sending. This letter covers the
> one-off Endpoint Assurance assessment only. It is not the retainer Master
> Service Agreement (Managed Patching / Full Endpoint Management), which is
> a separate, longer-running document with its own renewal and service-level
> terms, tracked under PAT-112. As of this letter's drafting, no PAT-112 MSA
> document exists yet in this repository - if that changes before this
> letter is used, check the two for contradictions (particularly on
> liability, data handling, and termination) and align rather than duplicate.

# Endpoint Assurance - Engagement Letter

**Between:** Patched.im ("Patched", "we", "us") and [CUSTOMER LEGAL NAME]
("the Customer", "you"), of [CUSTOMER REGISTERED ADDRESS].

**Engagement:** a one-off Endpoint Assurance assessment, as scoped in the
signed scoping questionnaire dated [SCOPING QUESTIONNAIRE DATE] and priced
in the order confirmation dated [ORDER DATE].

**Fee:** [FEE AMOUNT], one-off, fixed, ex-VAT, as confirmed on the signed
order. This letter and the signed order are the two documents that together
set the commercial terms; where they conflict, the signed order governs.

---

## 1. What this engagement is

A time-boxed, instrumented assessment of the Customer's endpoint estate,
producing a written report as described in Section 3. This is a fixed-term
engagement with a defined start and end date, not a subscription and not an
ongoing service. It does not include fixing anything the report finds -
applying the remediation plan is what a Managed Patching or Full Endpoint
Management retainer buys, and is out of scope here.

## 2. What is assessed, and what is not

This mirrors, and does not extend, Section 4.4 of the assessment report
template.

**In scope:**

- The endpoints named in the signed scoping questionnaire, for the
  instrumentation window defined in Section 4.
- What the Patched endpoint agent can observe on those devices: CVE
  exposure and configuration posture (Section 2.1 of the report), standing
  local-administrator accounts (Section 2.2), and application inventory for
  licence and shadow-IT visibility (Section 2.3).
- The Customer's own written policy records, where provided, for comparison
  against what the agent observes.

**Out of scope, explicitly:**

- **This is not a penetration test.** No attempt is made to exploit a
  vulnerability, move laterally, escalate privilege, or test whether a
  control can be defeated. Findings are observational, not adversarial.
- **This is not a certification.** The report's framework mappings to Cyber
  Essentials, ISO 27001 Annex A, and UK GDPR Article 32 identify which
  control area a finding relates to. They are not, and must not be
  represented as, a Cyber Essentials certificate, an ISO 27001 audit
  opinion, or a legal opinion on regulatory compliance.
- Network infrastructure, cloud infrastructure, and any system outside the
  named endpoints (for example the Customer's servers, firewalls, or SaaS
  configuration) are out of scope unless separately agreed in writing.
- Devices outside the count and platform split agreed in the scoping
  questionnaire. A device discovered mid-engagement that was not declared
  is noted to the Customer and added only by written agreement, which may
  affect the fee.
- [specialist input required: list anything else declared out of scope for
  this specific engagement on the signed scoping questionnaire.]

## 3. Deliverable

One written report, structured as: a plain-language executive summary; the
CVE and configuration posture baseline; standing local-admin exposure;
licence and shadow-IT visibility; and a sequenced remediation plan setting
out what to fix first and why. Delivered to the named recipient over a
signed, time-limited download link. [LEGAL: confirm the link's expiry rule
to state here in customer-facing language - the report template currently
says "expires after first use or [specialist input required: confirm the
configured expiry window]"; this letter and the report template must state
the same rule once it is decided.] The report is not emailed as an
attachment and the link must not be forwarded outside the named recipient.

## 4. Instrumentation window

The assessment runs over an instrumentation window of **2 to 4 weeks** from
the agreed start date, the exact length confirmed on the signed order based
on estate size and the deadline identified in scoping (question D4/D5 on
the scoping questionnaire).

During this window, a Patched endpoint agent is installed on each in-scope
device to collect the data described in Section 2. **At the end of the
window, the agent is removed from every device it was installed on.** No
Patched agent, and no Patched software of any kind, remains installed once
this engagement concludes, unless the Customer separately signs a retainer
that includes ongoing agent deployment.

## 5. Data handling and retention

**What is collected:** device-level configuration state, installed
application inventory with last-used and launch data, matched CVE findings,
and local-administrator account counts, as described in Section 2. The
agent does not collect the content of files, emails, or messages, and does
not collect keystrokes or screen contents. [LEGAL: confirm this description
is complete and accurate against the actual agent's data-collection scope
before this letter is used - it must match what the agent genuinely
collects, not an approximation.]

**Where it goes:** collected data is stored in Patched's production systems,
associated with the Customer's tenant, and is not shared with any third
party except [LEGAL: confirm any subprocessors that touch this data, e.g.
hosting/infrastructure providers, and list them here or reference a
subprocessor list].

**How long it is kept:** [LEGAL: confirm the retention period for
assessment data after the engagement ends - the report template does not
set this and no default exists yet. State it here as a fixed period, not
"as long as needed."]

**At the end of the engagement:** the agent is removed per Section 4. The
Customer's report remains available at the signed download link until it
expires (Section 3). [LEGAL: confirm what happens to the underlying
collected data after the retention period in this paragraph - deleted,
anonymised, or retained in an aggregate/de-identified form for product
improvement - and state it plainly. Silence here is not an acceptable
answer in a contract.]

If the Customer proceeds to a retainer, the same data forms the baseline
for ongoing reporting and is retained under the terms of that retainer's
agreement rather than this letter.

## 6. Credit against onboarding

If the Customer signs an order for a Managed Patching or Full Endpoint
Management retainer within **90 days** of the report date stated on the
delivered report, the fee paid for this engagement is **credited in full**
against the onboarding cost of that retainer. This matches the public
commercial terms published at the time of this engagement. The credit
applies once, against the first retainer order signed within the window,
and is not transferable to a different customer entity or reissued if the
retainer is later cancelled.

## 7. Fees and payment

[LEGAL: confirm standard payment terms - invoicing point (on signature, on
report delivery, or split), payment due period (e.g. 14 or 30 days), and
what happens on late payment. None of this is set elsewhere in this repo.]

## 8. Liability

[LEGAL: confirm the liability cap. Common structures for an engagement this
size are a cap set at the fees paid under this engagement, or a fixed
monetary figure - recommend starting from "capped at the fees paid under
this engagement" as a simple, defensible default for a solicitor to review,
rather than an unrelated fixed figure.] Nothing in this letter is intended
to exclude or limit liability for death or personal injury caused by
negligence, fraud or fraudulent misrepresentation, or any other liability
that cannot lawfully be excluded or limited. [LEGAL: confirm whether
professional indemnity insurance is held and, if the Customer's sector
(regulated financial services, gambling, or trust and company service
provision - see scoping questionnaire Section D) requires it to be
disclosed here, state the cover level.]

## 9. AI use disclosure

Parts of Patched's internal tooling, including elements of this document's
drafting, findings triage, and report preparation, may involve AI-assisted
software. Every finding in the delivered report is reviewed and signed off
by a named human specialist before delivery (see the report cover page,
"Prepared by"); AI assistance does not replace that review and the
specialist named on the report is accountable for its content. [LEGAL:
confirm this disclosure meets current requirements for the Customer's
sector, particularly for regulated financial services or public-sector
customers, where AI-use disclosure expectations are moving and
sector-specific.]

## 10. Term and termination

This engagement runs from the agreed start date until the report is
delivered, or until terminated earlier under this section.

Either party may terminate this engagement on [LEGAL: confirm notice
period, e.g. 14 days] written notice.

**If the engagement ends early:**

- The Customer is invoiced for work completed to the point of termination,
  calculated as [LEGAL: confirm the method - e.g. pro-rata against the
  instrumentation window elapsed, or a fixed early-termination fee].
- Patched removes its agent from every device it was installed on, per
  Section 4, regardless of how the engagement ended.
- If sufficient data was collected before termination to produce a partial
  report, the Customer may request one; it is marked as based on an
  incomplete instrumentation window rather than the full assessment.
- The Section 6 credit against onboarding does not apply to a terminated
  engagement that did not reach report delivery, unless otherwise agreed in
  writing.

## 11. Governing law and jurisdiction

This letter is governed by the laws of [LEGAL: confirm governing law -
England and Wales is the expected default for a UK-based engagement, but
must be confirmed, not assumed], and the parties submit to the exclusive
jurisdiction of the courts of [LEGAL: confirm, expected to match the
governing law choice above].

## 12. Signatures

| | Patched.im | [CUSTOMER LEGAL NAME] |
|---|---|---|
| Name | | |
| Title | | |
| Date | | |
| Signature | | |

---

*End of engagement letter template. Remove the warning block at the top,
this line, and every remaining `[LEGAL: ...]` and `[specialist input
required: ...]` marker before this document is used with a customer.*
