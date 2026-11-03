# Portal rubric

Last compiled: 2026-09-30.

This is a checklist a model or a person uses to judge portal screenshots against the design and copy rulings recorded in Linear. Each rule is numbered by group (C for Copy, D for Honesty of data, L for Layout, N for Navigation, T for Theming) and states one thing that should be visible, or absent, on screen. Every rule carries a `Source:` line naming the ticket, comment date or document it comes from. Rules that cannot be judged from a screenshot alone are left out.

**The 24 September 2026 revision wins.** The 12 September 2026 rulings on PAT-1602 were the original design decisions for a managed-service portal. A comment on PAT-1602 dated 24 September 2026 revised seven of those rulings for the SaaS reset (see the decision document "Decision: Patched resets as Endpoint Assurance SaaS (2026-09-19)"). Where the two disagree, this rubric follows the 24 September revision, not the 12 September originals. The Contradictions section below lists what changed and why.

## Copy

C1. No wording anywhere states or implies that a Patched specialist acts, decides or does something for the customer.
Source: PAT-1602 (24 Sept 2026 revision, ruling 3); PAT-2130.

C2. No specialist-time, drawdown, or "days remaining" figure, tile or bar appears anywhere on screen.
Source: PAT-1602 (24 Sept 2026 revision, ruling 3); PAT-2130.

C3. No tier name ("Assurance" or "Managed") or tier chip is shown to the customer; the header's subscription-state slot renders empty until a real state is available, and nothing is inferred into it.
Source: PAT-1602 (24 Sept 2026 revision, ruling 5); PAT-2130.

C4. No live or in-progress removal-campaign copy or view appears anywhere on screen.
Source: PAT-1602 (24 Sept 2026 revision, ruling 2); PAT-2130.

C5. No "coming soon" wording and no staggered-tier framing (for example a feature shown as locked or gated behind an upgrade) appears anywhere on screen.
Source: PAT-2127 (copy rules, ruled 24 Sept 2026).

C6. Copy says "estate", never "fleet", when referring to a customer's set of devices.
Source: portal AGENTS.md house style; root AGENTS.md; PAT-2127.

C7. No em dash character (Unicode U+2014) appears anywhere in customer-facing copy.
Source: portal AGENTS.md house style; root AGENTS.md; PAT-2127.

C8. Copy uses UK spelling throughout.
Source: portal AGENTS.md house style ("UK English").

C9. Copy is written in plain, customer-facing language rather than internal operator jargon (for example "what we can see of your estate" rather than "coverage", a plain description of why devices stopped reporting rather than "drift event").
Source: PAT-1602 (12 Sept 2026, "Copy is written for the customer, not the operator"; not touched by the 24 Sept revision).

C10. Outcome copy says "identified" where Patched identified an issue and says "completed" only where Patched itself completed the fix; a customer's own remediation is never worded as something Patched completed.
Source: PAT-1851 (17 Sept 2026 ruling, Attribution).

C11. A platform value renders as its proper display form (for example "macOS", "Windows"), never as a raw lower-case internal code (for example "macos").
Source: PAT-2119.

## Honesty of data

D1. A device that has not reported reads as not yet reported, silent or quiet, and never as a failure or a compliance breach.
Source: PAT-1602 (12 Sept 2026 design ruling, unaffected by the 24 Sept revision); PAT-1843 (Cyber Essentials v3.3 14-day window).

D2. Devices that have not reported are never counted as compliant anywhere on screen.
Source: PAT-1602 (12 Sept 2026, "the 26 unseen are not counted as compliant anywhere in the portal or in any report").

D3. Every figure on screen carries its denominator (for example "222 of 248"), never a bare number alone.
Source: PAT-1602 (design language inherited from the console, rule 6; and the 12 Sept 2026 coverage ruling).

D4. CVE findings and CIS/compliance findings render in visually distinct sections or tables, never interleaved into one list or blended into a single count.
Source: PAT-1602 (12/13 Sept 2026 ruling, "why the findings split").

D5. A finding's match confidence renders one of the platform's own states (Vendor-confirmed, Confirmed, Possible, Unrecognised), never collapsed to a simple Confirmed/Unverified pair, and an absent or unrecognised value never renders as Confirmed.
Source: PAT-1842.

D6. A CVE finding with no published description states explicitly that no description has been published; it does not silently disappear from the list.
Source: PAT-1841.

D7. An unknown fixed version renders as "latest vendor release" (matching the PDF report's wording), never as a blank cell.
Source: PAT-1841.

D8. Affected device names are never listed in the tenant-wide findings table; device-level detail lives on the device page instead.
Source: PAT-1841.

D9. Evidence-basis wording (identifier match, name match only, or unknown) never appears on, or is conflated with, a CVE finding's match-confidence value.
Source: PAT-1842.

D10. The absence of a "Protected" badge reads as "not known to be protected", never as "confirmed unprotected".
Source: PAT-1844.

D11. Extension rows never carry a "Protected" badge, and the page never implies extensions were checked for protection.
Source: PAT-1844.

D12. CIS control coverage distinguishes, wherever the data supports it, five states on screen: measured and passing, measured and failing, could not be determined (counted as failing), not applicable, and deliberately out of scope. Nothing implies that absence of evidence is a pass.
Source: PAT-1859; PAT-1849.

D13. A control with no CIS identifier (unmapped, or a Patched-only check) states so explicitly; it never renders as a blank and never borrows another control's number.
Source: PAT-1859.

D14. No rule count, control number or coverage figure is invented or computed on the portal side; only what the platform endpoint reports is shown.
Source: PAT-1859; PAT-1849.

D15. Wherever CIS coverage figures appear, the benchmark, benchmark version and the platform mix (for example macOS and Windows) that produced them are also stated.
Source: PAT-1859.

D16. An out-of-scope control states the reason (for example, manual review) rather than just the word "out of scope".
Source: PAT-1859.

D17. An accepted exception stays visible with its status, named acceptor and date; nothing about the layout makes it read as resolved.
Source: PAT-1846; PAT-1785 (register rule).

D18. No monetary or time-saving figure is shown unless it is backed by customer-supplied cost data.
Source: PAT-1851 (Outcomes guardrail, both the original ticket body and the 17 Sept 2026 ruling).

D19. The report catalogue and report history show only report types the platform endpoint actually returns; nothing is hardcoded or invented, and history rows show a name and date, never a raw UUID.
Source: PAT-1847.

## Layout

**Phone-width rules apply to phone-supported routes only (Andy ruling 2026-09-30, PAT-2329).** Phones are a supported quick-look tier, not a full-parity one. The phone-supported routes are `/` (Overview), `/software/alerts`, `/devices/{device_id}` (the device page itself, not its Compliance, Software, Hardware, Vulnerabilities or Evidence tabs), `/requests` and `/feedback`; `main.PHONE_SUPPORTED_ROUTES` is the list. Every other signed-in page is dense: it is judged at 1280px and above, is not walked or screenshotted at 390px, and below 768px shows one muted note under its heading, "This page is best viewed on a larger screen." That note is expected on a dense page at phone width and is not a defect; a phone-width rule (L12) is never applied to a dense page.

L1. No table on any portal page is clipped, and no table overflows its containing card, at any width from 1280 to 1920px; a table wider than its card scrolls horizontally instead.
Source: PAT-1843; PAT-1846; PAT-2119; PAT-2120.

L2. A search input is not flush against its card's border; visible spacing separates it from the edge.
Source: PAT-1843.

L3. Shared columns (for example Product, Platform, Installs, Evidence) line up at the same horizontal position across sibling tables on one page.
Source: PAT-1843; PAT-1844.

L4. All groups or cards on one page share one consistent container idiom: one left edge and one heading treatment, not a mix of two different card styles.
Source: PAT-1844.

L5. KPI or summary rows render horizontally at normal desktop widths, not as a vertical stack.
Source: PAT-1843; PAT-1844; PAT-1846; PAT-1859.

L6. Row heights within a table are even, and a pill sitting beside text sits on that text's baseline rather than floating above it.
Source: PAT-1846.

L7. There is one obvious place on the Software page to approve or act on a given product; the same product is not independently actionable in two separate, overlapping tables.
Source: PAT-2120 (Done-when criteria).

L8. Filters and bulk-action controls sit directly above the table they apply to.
Source: PAT-2120 (Done-when criteria).

L9. Explanatory or hint text sits next to the thing it explains rather than appearing as separate, scattered paragraphs elsewhere on the page.
Source: PAT-2120 (Done-when criteria).

L10. The Approval column's controls (the status select, the Apply button, the Hide checkbox and its label, and the state pill) are fully visible and not clipped or truncated, at any width from 1280 to 1920px.
Source: PAT-2119.

L11. The Evidence date column's text does not wrap over more than two lines at 1280px width.
Source: PAT-2119.

L12. On a phone-supported route at 390px, no table text breaks mid-word or renders one character per line, and a table wider than its card either stacks into label/value rows (the `.table-stack` pattern) or scrolls inside its card; it never forces the page to scroll sideways.
Source: Andy ruling 2026-09-25, PAT-2128; precedents PAT-2136, PAT-2137; scoped to phone-supported routes by Andy's ruling of 2026-09-30, PAT-2329.

L13. No date or time cell in any portal table wraps beyond two lines at 1280px width.
Source: Andy ruling 2026-09-25, PAT-2155; generalises L11.
The walker (`e2e/walk/walk.py`) enforces this rule at 1280px (PAT-2162); and at 1440px, where secondary columns can make a date column narrower.

## Navigation

N1. Findings, Devices, Software, Exceptions and Reports remain top-level destinations in the rail. The rail groups primary estate destinations separately from quieter Governance and Operations destinations; grouping must not remove or orphan a route.
Source: PAT-1851 (17 Sept 2026 ruling); PAT-2185.

N2. Posture and Attention content appears as sections within the Overview page, not as new top-level rail items.
Source: PAT-1851 (17 Sept 2026 ruling).

N3. CIS control coverage appears on, or directly adjacent to, the Overview; it is not a new permanent top-level rail item.
Source: PAT-1859.

N4. Nothing on screen implies a tenant switcher, a cross-tenant comparison, or a ranked "which customer needs attention" view; the portal shows one customer's own estate only.
Source: PAT-1602 (12 Sept 2026, "the portal deliberately differs"; unaffected by the 24 Sept revision).

N5. The portal's landing screen is a single-estate overview, not a customer-selection or ranking screen.
Source: PAT-1602 (12 Sept 2026, unaffected by the 24 Sept revision).

N6. Reporting, Quiet and Silent device states switch through one shared horizontal control, not through a vertical stack of separate page sections.
Source: PAT-1843.

N7. The Software page's kind filter (application or extension) and its decision-state groups stay reachable on the one `/software` page; they do not require navigating to a separate page.
Source: PAT-1798 (referenced in PAT-1844); PAT-1844.

N8. The navigation shows no "Recommendations" item until that page exists; when it does, it is visible to every customer, with no tier or plan gate.
Source: PAT-2124 (Andy's ruling, 25 Sept 2026); PAT-1602 (13 Sept 2026 nav hierarchy comment, superseded).

## Theming

T1. Every signed-in page offers a light/dark theme toggle in the header.
Source: PAT-1602 (12 Sept 2026 ruling 4, unaffected by the 24 Sept revision); portal AGENTS.md house style.

T2. The page never flashes the wrong theme on load; the stored or system-preferred theme is applied before first paint.
Source: portal AGENTS.md house style (PAT-1641).

T3. Issued documents (PDF reports, the assessor pack) always render light, regardless of the on-screen theme toggle's current setting.
Source: PAT-1602 (12 Sept 2026, `11-portal-reports.html` ruling); PAT-1859 comment.

T4. The left rail and the footer stay permanently dark and do not change with the light/dark theme toggle.
Source: portal AGENTS.md house style.

T5. No colour appears on screen outside the existing token set; no new colours are introduced.
Source: PAT-1602 (design language inherited from the console, rule 1).

T6. Signal orange is used only for action or selection, never to carry status; danger and warning colours carry severity, and green is used sparingly.
Source: PAT-1602 (design language inherited from the console, rule 2).

T7. Charts render as stacked bars, never as pie charts.
Source: PAT-1602 (design language inherited from the console, rule 5).

T8. Text uses the platform system font throughout; a monospace font appears only for evidence, versions, counts and identifiers, never for prose; no web or Google fonts are loaded.
Source: PAT-1602 (design language inherited from the console, rule 3); portal AGENTS.md house style.

## Contradictions

### Resolved by the 24 September revision

The 24 September 2026 comment on PAT-1602 explicitly revises the following 12 September 2026 rulings. Both sides are recorded here for traceability; the rubric above follows the 24 September side only.

R1. **Disposition authority.** 12 Sept: staff only records a disposition; the customer can only raise a request (PAT-1602 12 Sept ruling 1; PAT-1841's "request affordances, not accept controls"; PAT-1848 and PAT-1860, both since cancelled, built a specialist decision queue on this premise). 24 Sept: a named customer user records the disposition directly, with a required reason and review date, labelled customer-attested (PAT-1602, 24 Sept revision, ruling 1). Resolved: customer-attested wins; PAT-1848 stayed cancelled and PAT-1860 moved to RoadMap.

R2. **Removal campaigns.** 12 Sept: the customer sees a removal campaign's live per-device progress (PAT-1602 12 Sept ruling 2; artboard `13-portal-campaign.html`). 24 Sept: removal campaigns are retired; no campaign view ships in v1 (PAT-1602, 24 Sept revision, ruling 2; PAT-2130). Resolved: retired; the artboard is kept only in case removal returns as a paid capability.

R3. **Specialist time.** 12 Sept: a drawdown tile shows "9.2 of 10 days remaining" with a period-end date (PAT-1602 12 Sept ruling 3). 24 Sept: no days, drawdown or specialist mention appears anywhere in customer copy (PAT-1602, 24 Sept revision, ruling 3; PAT-2130). Resolved: retired.

R4. **Tier in the header.** 12 Sept: the header names the customer's tier, "Assurance" or "Managed" (PAT-1602 12 Sept ruling 5, and the 12 Sept decision comment settling the exact wording). 24 Sept: the tier chip is removed; the header carries an empty `subscription-state` slot instead, and the internal `assurance`/`managed` values stay platform-side only (PAT-1602, 24 Sept revision, ruling 5; PAT-2130). Resolved: no tier chip.

R5. **Report tier gating.** 17 Sept: nine report types go customer-facing and access gates on assurance versus managed (PAT-1847 ruling). PAT-1856 was split out to build that gate. 24 Sept: under one plan, every tenant gets every customer-facing report; PAT-1856 is cancelled as moot (PAT-1602, 24 Sept revision, knock-on effects; PAT-1856 issue record). Resolved: no report tier gate ships.

R6. **Hardware Health PDF section.** 17 Sept: the section is gated to `managed`-tier tenants only, marked provisional pending an explicit product call (PAT-1847 out-of-scope note; `internal/handlers/portal.go:860-884`). 24 Sept: the gate is removed so every tenant's report includes it (PAT-2130, item 5; shipped and verified per the PAT-2130 comment of 25 Sept 2026). Resolved: gate removed.

R7. **Recommendations nav item and its tier gate.** 13 Sept: PAT-1602's nav hierarchy comment placed a "Recommendations" item under Findings, gated to the Endpoint Assurance tier only. 24 Sept: the one-plan revision removed tiers but did not name this item. Ruled by Andy on 25 Sept 2026 (PAT-2124): not in v1; if PAT-1691 later ships the page, it is shown to every customer with no gate. Resolved: see N8.

### Open, not resolved by the 24 September revision

None as of 25 September 2026.

## Sources not found

None. Every source named in PAT-2127 was located and read in full, including every comment on PAT-1602, PAT-1841 through PAT-1851, PAT-1859, the "Decision: Patched resets as Endpoint Assurance SaaS (2026-09-19)" document, both AGENTS.md files, and PAT-2119, PAT-2120 and PAT-2130. PAT-1856 and PAT-1860 were also read for the cancelled/moot context the ticket asked to check.
