# PAT-1047 redesign v2: operator workflow

The first PAT-1047 implementation is rejected. It changed colour, type,
spacing and navigation chrome, but preserved the old page, card and tab mental
model. The PNG mockups in this directory remain useful visual references for
light-first density, system type, restrained orange and familiar admin
controls. They are not the information-architecture contract.

This document is the implementation contract for the replacement.

## Outcome

An operator must be able to answer three questions without navigating through
several dashboards:

1. Which customer needs attention?
2. Why does that customer need attention?
3. What evidence or existing Patched action resolves the issue?

The console is therefore organised around progressive investigation:

`all customers -> customer priorities -> affected devices -> device evidence`

Data inventory, configuration and administration remain available, but they
support this workflow rather than defining the default page anatomy.

## Structural rules

- Do not recreate a left rail plus horizontal page tabs plus horizontal
  sub-tabs.
- Do not lead pages with a row of metric cards.
- Do not use several equal cards when one ranked list and one detail inspector
  express the relationship more clearly.
- Do not invent case state, remediation APIs, MDM actions or remote-control
  actions. Use existing data and existing actions only.
- Preserve every current route, hash, loader, form, modal, confirmation, RBAC
  gate and PAT-854-safe value boundary.
- Preserve deep links. A legacy hash may activate a new navigator destination
  and panel, but it must not fall back silently to Home.
- Use the system font. Use `estate`, never `fleet`, in visible copy. Do not use
  em dashes in visible copy.

## Application frame

Desktop uses three persistent regions:

1. **Global rail, 64px.** Patched lockup, Work, Customers, Operations and
   Administration. It establishes global context only.
2. **Context navigator, 280px.** Its content changes with the selected global
   destination or customer. Service Health exposes Infrastructure and
   Automations. Admin Tools exposes Billing, Catalogue, Credentials, Docs,
   Leads, Logs and Reports. A customer exposes the customer workflow below.
3. **Workspace.** The active list, investigation or specialist tool.

The context navigator is the material redesign. It replaces both the old
tenant-sidebar swap and PAT-1047 v1's horizontal workload and secondary tab
bars. The operator can see where a specialist surface lives without opening
menus or scanning two tab rows.

The top utility bar is compact and contains customer switching, global search
when available, environment/impersonation state and operator identity. It does
not duplicate page navigation.

## Work: customer-priority command centre

Work replaces Home. It is not a generic dashboard and not a global per-device
queue.

The primary region is a ranked customer list. Each row contains customer,
overall state, the strongest current reason for attention, affected-device
count and last evidence time. Selecting a row updates an adjacent inspector
without navigating away.

The inspector explains:

- the signals contributing to the customer's state;
- how many devices are affected;
- when the evidence changed;
- direct links into the relevant customer priority, patching, compliance or
  device view.

Service Health and Automations are a compact status rail. Recent cross-customer
activity is secondary and sits below the priority workspace. There is no
summary-card strip.

## Customers

Customers uses list-detail anatomy:

- searchable and sortable customer list;
- selected-customer preview with service tier, device coverage, strongest
  signals and an `Open customer` action;
- create/offboard and existing guarded actions remain reachable.

On narrow screens the preview becomes a full-width drawer.

## Customer workspace

The context navigator starts with customer identity, service tier, estate
coverage and last evidence time. It exposes these workflow destinations:

### Priorities

Default customer destination. It combines the current Overview and Needs
Attention data into a ranked signal list and a detail inspector.

Selecting a signal shows:

- affected devices;
- severity and evidence age;
- the available existing action or route;
- the related recent activity.

Do not pretend an advisory finding can be remotely remediated. Where Patched
has no action, label the next step as review or evidence, not fix.

### Devices

Inventory and device-health views. Use a dense master list with filters and a
selected-device preview. Opening a device enters the device workspace without
losing customer context.

### Patching

Vertical child destinations:

- Patch & Deploy
- Software Catalogue
- Application Control, preserving its feature gate
- Browser Extensions

### Assurance

Vertical child destinations:

- Compliance Status
- CIS Controls
- CVE Findings

### Evidence

Vertical child destinations:

- Reports
- Software Metering
- Enforcement Audit
- Shadow IT

### Customer setup

Vertical child destinations:

- Account
- Customer Access
- Deploy Agent
- Webhooks
- Runbook

All 19 current tenant `data-tab` values remain wired. The new navigator maps
to them rather than adding another navigation state model on top.

## Device workspace

Device detail becomes a diagnostic workspace, not six equal top tabs.

The customer context navigator stays present. Inside the workspace:

- a compact identity header provides back navigation and preserves guarded
  revoke/delete actions;
- a narrow device navigator exposes Summary, Hardware, Software, Patching,
  Compliance and Activity vertically;
- Summary uses a split investigation view:
  - left/centre: ranked issues and posture signals;
  - centre/right: selected issue evidence, affected software or control data,
    and the existing relevant action;
  - right/bottom: recent activity and immutable device facts.

Hardware, Software, Patching, Compliance and Activity reuse the current loaders
and content, but render inside the same diagnostic frame. Browser extensions
remain a Software subsection. Security inventory remains under Hardware.

At tablet width the evidence inspector moves below the selected signal. At
phone width both navigators become drawers, the selected signal opens a
full-width detail panel, tables gain horizontal containment, and every primary
action remains reachable without hover.

## Shared component anatomy

Use a small component contract:

- global rail;
- context navigator;
- utility bar;
- workspace header;
- command row;
- master list;
- detail inspector;
- signal row;
- definition list;
- activity timeline;
- dense data table;
- filter popover;
- status badge;
- loading, unavailable, empty and error states;
- modal/drawer.

Cards are reserved for a genuinely bounded object. Layout grouping should use
background, border and spacing before radius or shadow.

## Acceptance

The redesign is not complete unless rendered evidence shows:

- Work with ranked customer selection and its inspector;
- Customers list-detail;
- Service Health with its context navigator;
- an Admin Tools table with its context navigator;
- customer Priorities with selected signal detail;
- customer Devices;
- one Patching destination;
- one Assurance destination;
- Customer setup;
- device Summary split investigation view;
- one device specialist destination;
- narrow global, customer and device views;
- light and dark mode.

Review must explicitly compare PAT-1047 v1 against v2 and confirm that the
horizontal workload tab stack, metric-card-led page anatomy and isolated
device tab pages are gone.

## Rejected-branch defects that must not survive

- Use the customer portal's shared paper, snow, slate, graphite, rule and
  signal-orange tokens throughout the Console. This supersedes the temporary
  dashboard-only blue exception after live PAT-1047 acceptance feedback.
  Solid controls use the deeper signal token so white labels remain readable;
  success, warning and danger remain semantic rather than becoming orange.
- Delete `_ddRenderOverviewPosture()` and its invented client-side posture
  score. Do not manufacture assurance metrics from arbitrary deductions.
- Do not issue an additional enforcement-audit request whenever customer
  Overview activates. Reuse the existing source or load evidence only when its
  destination is selected.
- Remove the hidden duplicate `sidebar-identity` kept only for old tests.
  Update the role/identity contract and its tests instead.
- Preserve the original device data and action loaders. Do not merge or rename
  their functional keys merely to satisfy the rejected six-tab presentation.
- Static string tests are insufficient. Exercise navigation state, modal
  focus, RBAC visibility, list-detail selection and responsive behavior in the
  rendered acceptance pass.
