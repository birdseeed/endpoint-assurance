# Data Processing Agreement — template

> **STATUS: DRAFT — requires legal review before use with any customer.**
> This template is provided as a starting point. Have it reviewed by a qualified
> data protection solicitor before signing with any customer.

---

## DATA PROCESSING AGREEMENT

**This Data Processing Agreement ("DPA")** supplements the main service agreement
("Agreement") between:

**Controller:** [Customer legal entity name] ("Controller")

**Processor:** Patched Ltd, [registered address], Isle of Man ("Processor")

and is incorporated into the Agreement by reference. In the event of conflict,
this DPA takes precedence over the Agreement on matters of data protection.

---

## 1. Definitions

"**Personal Data**", "**Data Subject**", "**Processing**", "**Supervisory Authority**",
"**Data Breach**" have the meanings given in the UK GDPR / EU GDPR / IoM Data Protection
Act 2018 (whichever applies to the Controller).

"**Agent Data**" means the personal data listed in Schedule 1, collected by the Patched
endpoint agent from devices owned or managed by the Controller.

---

## 2. Subject matter, nature, and purpose of Processing

| Item | Detail |
|---|---|
| Subject matter | Device inventory, compliance posture, and software update activity for managed endpoints |
| Purpose | Provision of the Patched managed software patch service as described in the Agreement |
| Nature | Collection, storage, analysis, and secure deletion of Agent Data |
| Data subjects | Employees and contractors of the Controller to whose devices the agent is deployed |
| Duration | For the term of the Agreement, plus the retention periods in Schedule 1 |

---

## 3. Processor obligations

The Processor shall:

3.1 **Process only on documented instructions** from the Controller, unless required by law.
The instructions are: (a) process Agent Data to provide the services in the Agreement;
(b) process as described in Schedule 1; (c) process on the storage infrastructure listed
in Schedule 2. The Processor shall inform the Controller if it believes an instruction
infringes applicable data protection law.

3.2 **Ensure confidentiality.** Persons authorised to process Agent Data are bound by
confidentiality obligations.

3.3 **Implement appropriate technical and organisational measures**, including those
described in the Patched Security Overview document and in the codebase security controls
(Ed25519-signed agent-config, SHA-256 hash pinning, structured audit logging).

3.4 **Support data subject rights.** The Processor shall assist the Controller in
responding to requests from Data Subjects (access, erasure, portability, rectification)
within 5 business days of a Controller request, within the technical limits described in
`docs/gdpr-data-inventory.md` §9.

3.5 **Notify Data Breaches.** The Processor shall notify the Controller within 72 hours
of becoming aware of a Personal Data breach affecting Agent Data.

3.6 **Return or delete data** on termination of the Agreement. The Controller may request
export within 30 days of termination; thereafter, the Processor shall securely delete all
Agent Data within a further 30 days, unless required by law to retain it.

3.7 **Provide audit assistance.** The Processor shall make available information necessary
to demonstrate compliance and allow for audits conducted by the Controller (or mandated
auditor) on reasonable notice (minimum 30 days), not more than once per 12-month period.

---

## 4. Sub-processors

4.1 The Controller grants general written authorisation for sub-processors listed in
Schedule 2. The Processor shall provide 30 days' prior written notice of any intended change
and give the Controller the opportunity to object on data protection grounds.

4.2 Sub-processing contracts shall impose equivalent data protection obligations.

---

## 5. International data transfers

If Agent Data is transferred outside the EEA / UK / Isle of Man to a country not recognised
as providing equivalent protection, the transfer shall be covered by the UK International
Data Transfer Agreement (IDTA) / EU Standard Contractual Clauses (Annex to this DPA) or
an equivalent approved mechanism.

---

## 6. Term and termination

This DPA is in force for the duration of the Agreement and terminates automatically on
termination of the Agreement, subject to the data deletion obligations in §3.6.

---

## Schedule 1 — Personal data processed

| Category | Fields | Data subjects | Retention |
|---|---|---|---|
| Device identity | `hw_uuid`, `serial`, `hostname` / `computer_name` | Employees / contractors with assigned devices | 90 days rolling after last inventory upload |
| Software inventory | App list + versions linked to device identity | As above | 90 days rolling |
| Install / update history | Device UUID + app label + action + timestamp | As above | 12 months |
| Usage metering | App label + last-used timestamp per device | As above | 90 days rolling |
| On-demand log bundles | Redacted agent logs (see §6 of data inventory) | As above | 30 days |

Special category data: **none** — the service does not process special category data.

---

## Schedule 2 — Sub-processors

| Sub-processor | Role | Location | Transfer mechanism |
|---|---|---|---|
| [Cloud hosting provider — TBC] | Infrastructure hosting for the Patched platform | [TBC] | [TBC — SCCs or adequacy decision] |
| VirusTotal (Google LLC) | Hash lookup only — **no personal data transferred** (SHA-256 hashes of app installers only) | USA | N/A — no personal data |

---

## Schedule 3 — Technical and organisational measures

The Processor maintains the following measures at minimum:

- **Encryption in transit:** TLS 1.2+ for all agent-to-platform communications
- **Encryption at rest:** platform storage encrypted at rest (AES-256 or equivalent)
- **Authentication:** agent authenticates with per-tenant bearer token + HMAC-SHA256 per-request signature; no single credential can access another tenant's data
- **Access control:** platform staff access is role-based with MFA and audit logging
- **Signing and integrity:** agent-config and hash catalogues are Ed25519-signed; the agent verifies signatures before trusting any update instruction
- **Secrets management:** no secrets in source code or CI logs; HSM-backed key management (PAT-497)
- **Vulnerability management:** dependency scanning and CodeQL / Semgrep SAST in CI (PAT-509, PAT-510); quarantined legacy package-maintenance workflows are not an operational security control
- **Incident response:** security incidents are notified to the Controller within 72 hours

---

## Signatures

| Controller | Processor |
|---|---|
| Name: | Name: |
| Title: | Title: |
| Date: | Date: |
| Signature: | Signature: |

---

*Template version:. Review with legal counsel before signing.*
