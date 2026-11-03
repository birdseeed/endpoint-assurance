# GDPR data inventory — Patched endpoint agent

Patched acts as a **data processor** on behalf of the customer (the data controller).
This document covers data collected by the endpoint agent and transmitted to the Patched platform.

> **Legal basis for all collection:** Legitimate interest of the data controller
> (Article 6(1)(f) GDPR) — operating a managed software patch programme on corporate
> devices. Applies in IoM under the Data Protection Act 2018 (GDPR equivalent).

---

## 1. Device identity fields

These fields identify the managed device. Where a device is assigned to a named individual,
they constitute **personal data** (pseudonymous identifier linked to a natural person).

| Field | Example value | Personal data? | Legal basis | Retention |
|---|---|---|---|---|
| `hw_uuid` / `device_id` | `A1B2C3D4-...` | **Yes** — pseudonymous device ID; links to individual via employer's asset register | Legitimate interest | As per retention policy (§5) |
| `serial` | `C02XG0JFHV2N` | **Yes** — pseudonymous; links to individual via employer's asset register | Legitimate interest | As per retention policy (§5) |
| `hostname` / `computer_name` | `andys-macbook-pro` | **Yes** — often contains name or employee ID; treat as personal | Legitimate interest | As per retention policy (§5) |
| `tenant_id` | `uuid` | No — B2B organisation identifier, not an individual | Contract | Lifetime of contract |
| `arch` | `arm64` | No | — | — |
| `model` / `hw_model` | `MacBook Pro (2023)` | No | — | — |
| `ram_gb` | `16` | No | — | — |
| `disk_total_gb` | `512` | No | — | — |
| `disk_free_gb` | `234` | No | — | — |
| `last_boot` | ISO timestamp | No | — | — |

---

## 2. OS and compliance fields

These fields describe the security posture of the device. They are not directly personal
but are associated with the personal device identity fields above.

| Field | Example value | Personal data? | Notes |
|---|---|---|---|
| `os_version` | `15.5` | No | — |
| `os_build` | `24F74` | No | — |
| `filevault` / `bitlocker` | `on` | No | — |
| `gatekeeper` | `on` | No | — |
| `secure_boot` | `full` | No | — |
| `firewall` | `on` | No | — |
| `sip_status` | `enabled` | No | macOS only |
| `cis_score` | `85/100` | No | Aggregate compliance score |

---

## 3. Installed application inventory

Per-device list of managed applications and their update state.

| Field | Example value | Personal data? | Notes |
|---|---|---|---|
| `label` | `googlechrome` | No | — |
| `name` | `Google Chrome` | No | — |
| `installed_version` | `125.0.6422.76` | No | — |
| `available_version` | `126.0.0.1` | No | — |
| `state` | `update_available` | No | — |
| `last_action` | `installed` | No | — |
| `last_action_at` | ISO timestamp | No | — |
| `verified_signer` | `Google LLC` | No | — |
| `failure_reason` | `sha256_mismatch` | No | — |

Combined with the device identity fields, the application inventory links to an individual
and is therefore **in-scope personal data** in aggregate.

---

## 4. Provenance and install events

Each install or update action generates a provenance record tied to the device UUID.

| Field | Personal data? | Notes |
|---|---|---|
| `device_id` / `hw_uuid` | **Yes** — pseudonymous | — |
| `label`, `version` | No | — |
| `action` (`installed`, `updated`) | No | — |
| `timestamp` | No | — |
| `verified_signer`, `sha256` | No | — |

The combination of device UUID + install timestamps creates an **activity history** for a
device (and implicitly for its assigned user). Treat provenance records as personal data.

---

## 5. Software metering (usage frequency)

Where enabled, the agent reads usage-frequency data from:
- **macOS:** Spotlight / `mdls` metadata (last-opened timestamps)
- **Windows:** UserAssist registry key (run count + last-run time)

| Field | Personal data? | Notes |
|---|---|---|
| App label + last-used timestamp | **Yes** — usage pattern linked to device → individual | Collected only when metering is enabled in agent-config |

Metering data reveals which apps the device user actually uses. It is personal data.
**Data minimisation:** only aggregate counts and last-used timestamps are transmitted;
no window titles, file paths, or input data.

---

## 6. On-demand log upload

The platform can request an on-demand log bundle via a directive in the signed agent-config.
Log files may contain contextual information, but the agent **redacts** the following before
upload:
- Home directory paths (may contain username)
- Proxy credentials (URL-embedded)
- Bearer tokens
- Any string matching `[A-Za-z0-9+/]{40,}=*` (key-like patterns)

| Data category | Personal data? | Notes |
|---|---|---|
| Log lines after redaction | Potentially — depends on content | Log upload is on-demand (explicitly requested per device); retention is 30 days on platform |

---

## 7. Data minimisation assessment

| Question | Answer |
|---|---|
| Is `hw_uuid` / `serial` necessary? | **Yes** — required to correlate per-device posture and update history. Without a stable device identifier, duplicate reports cannot be de-duplicated and per-device compliance cannot be tracked. |
| Is `hostname` necessary? | **Yes** — enables operators to identify devices in the dashboard. However, if a hostname contains a personal name, consider whether the employer's Acceptable Use Policy covers device naming. |
| Is metering necessary? | No more than aggregate counts — last-used timestamp per app is sufficient; full usage logs are not transmitted. |
| Is any data shared with third parties? | VirusTotal receives artifact **hashes** (SHA-256), not personal data. No personal data leaves the Patched platform to third parties. |

---

## 8. Retention policy (recommended — platform-side implementation required)

| Data type | Recommended retention | Implementation status |
|---|---|---|
| Inventory snapshots | 90 days rolling | **To be implemented platform-side** |
| Provenance / install events | 1 year | **To be implemented platform-side** |
| Metering records | 90 days rolling | **To be implemented platform-side** |
| On-demand log bundles | 30 days | **To be implemented platform-side** |
| Agent-config audit trail | 2 years | **To be implemented platform-side** |

Implementing automated retention deletion is a platform-side task. Until implemented,
inform customers of the target policy and commit to a timeline in the DPA.

---

## 9. Data subject rights

Under GDPR, the data subject (employee) has rights to access, rectification, erasure,
and portability. As data processor, Patched must support the data controller (employer)
in fulfilling these rights:

- **Access / portability:** platform must support export of all data associated with a
  `hw_uuid` within 30 days of a controller request.
- **Erasure:** platform must support deletion of all records for a `hw_uuid` within 30 days.
- **Rectification:** hostname and computer name are read from the device; corrections should
  be made at the device level and will propagate on the next inventory upload.

These capabilities need to be implemented as platform admin API endpoints.
Document as a gap until available.

---

## 10. Infrastructure and data residency

| Question | Current status |
|---|---|
| Platform region | **TBC — document before first regulated customer** |
| Data residency (EU/EEA/IoM compliant?) | **TBC** |
| Sub-processors | Cloud hosting provider (TBC), VirusTotal (hash lookup only, no personal data) |
| Data transfer mechanism (if outside EEA) | Standard Contractual Clauses (SCCs) if hosting outside EEA/IoM |

---

*See also: `docs/gdpr-dpa-template.md` — standard DPA for B2B customers.*
