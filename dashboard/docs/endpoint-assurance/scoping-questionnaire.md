# Endpoint Assurance - Scoping Questionnaire

**Template - PAT-1300.** Used before quoting an Endpoint Assurance engagement, to
band the fee correctly and to know what we are walking into before the
instrumentation window starts. Intended to be sent to the prospect as a form
(likely an MS Forms questionnaire on the Patched tenant) or worked through live
on the scoping call. Every question states its answer type. The final section
is internal only and must not be sent to the customer - see the notice there.

---

## A. About the organisation

**A1. Company name and primary trading address.**
*Answer type: free text.*

**A2. Sector, and whether the organisation is regulated (for example legal,
financial services, healthcare).**
*Answer type: free text.*

**A3. Who is completing this questionnaire, and their role (IT lead, office
manager, compliance officer, MSP contact)?**
*Answer type: free text.*

**A4. Who is the decision-maker for a Patched engagement if different from A3?**
*Answer type: free text.*

---

## B. Estate size and composition

Ask B1 to B4 as separate counts. In our experience the managed count alone
under-states the real estate significantly, which is why the unmanaged and
BYOD questions are asked on their own rather than folded into "how many
devices do you have".

**B1. How many company-owned, IT-managed laptops and desktops are in use,
split by platform?**
*Answer type: number - macOS, number - Windows.*

**B2. How many company-owned devices exist that IT does NOT currently manage
or enrol anywhere (for example a device bought outside the normal process, a
loaner, a device a leaver kept)?**
*Answer type: number, or "none known".*

**B3. How many contractors or freelancers currently have access to company
email, file storage, or systems on a device the company does not own?**
*Answer type: number, or "none".*

**B4. How many employees use a personally-owned device (their own laptop,
their own phone) to access company email or files, whether or not this is
officially sanctioned?**
*Answer type: number, or "none known".*

**B5. Are there any servers, kiosks, or shared/front-of-house machines that
should be counted separately from the per-person estate in B1?**
*Answer type: free text + number, or "none".*

**B6. Is the estate expected to grow or shrink materially in the next 6
months (for example a planned hire round, an office closure, an
acquisition)?**
*Answer type: free text, or "no change expected".*

---

## C. Device management and licensing

Ask C1 and C2 as separate questions. Holding a licence and having a device
actually enrolled are different facts, and the gap between them is often
itself a finding worth reporting.

**C1. Does the organisation hold Microsoft Intune licensing (standalone, or
bundled in Microsoft 365 Business Premium / E3 / E5)?**
*Answer type: yes / no / not sure.*

**C2. Of the managed device count in B1, how many devices are actually
enrolled in Intune (or another MDM) today, right now, verified rather than
assumed?**
*Answer type: number, or "not sure - would need to check".*

**C3. If devices are enrolled somewhere, which platform (Intune, Jamf,
another MDM), and is enrolment enforced or optional?**
*Answer type: free text.*

**C4. Is there a current endpoint agent, antivirus, or EDR product deployed?
If so, which one, and to how many devices?**
*Answer type: free text + number, or "none".*

---

## D. Regulatory posture and the driving deadline

**D1. Does the organisation hold, or is it seeking, any of the following?
Select all that apply: FCA authorisation, GSC (Gambling Supervision
Commission) licence, TCSP (Trust or Company Service Provider) registration,
none of these, other (specify).**
*Answer type: multi-select + free text.*

**D2. Is a Cyber Essentials or Cyber Essentials Plus certification (existing
or in progress) relevant to this engagement?**
*Answer type: yes - existing / yes - in progress / no / not sure.*

**D3. Is an ISO 27001 certification (existing, in progress, or planned)
relevant to this engagement?**
*Answer type: yes - existing / yes - in progress / no / not sure.*

**D4. What specific event is driving this engagement, and what is its date?
For example: a cyber insurance renewal, a regulator audit, a client due
diligence request, a Cyber Essentials renewal, a board request following an
incident elsewhere.**
*Answer type: free text (name the event) + date.*

**D5. Is there a cyber insurance policy in place, and if so, when does it
next renew?**
*Answer type: yes + renewal date / no / not sure.*

The date given in D4 (or D5, if that is the actual driver) is treated as the
engagement deadline. The instrumentation window and report delivery are
planned backwards from it, not from when the order is signed.

---

## E. Incumbent IT support

Patched sits alongside an existing MSP or in-house IT function rather than
replacing one. These questions establish the boundary between what the
incumbent already covers and what this assessment adds, not whether Patched
should replace the incumbent.

**E1. Is there a current MSP or IT support provider?**
*Answer type: yes (name) / no, handled in-house / no, no formal IT support.*

**E2. What does the incumbent MSP or in-house team currently cover? Select
all that apply: patching, antivirus/EDR, backup, helpdesk/user support,
device procurement, network/firewall, none of the above known.**
*Answer type: multi-select.*

**E3. Does the incumbent MSP or in-house team already produce any compliance
or security reporting (for Cyber Essentials, ISO 27001, insurance, or a
client)? If so, what and how often?**
*Answer type: free text, or "no reporting currently produced".*

**E4. Has the incumbent MSP been told this assessment is happening?**
*Answer type: yes / no / not yet, will confirm.*

---

## F. Line-of-business applications

Feeds catalogue onboarding - the Endpoint Assurance report only credits a
line-of-business application to the Patched software catalogue if it is
identified here or found during the instrumentation window. List every
application the organisation depends on to run its business, not just
Microsoft 365 and the browser.

**F1. For each line-of-business application, give: vendor and product name,
platform and processor architecture, deployed version, approximate number of
seats/users, business owner, business criticality, installer source and format,
and how it is currently kept up to date (vendor auto-update, manually by IT,
not updated/not sure). Say whether downloading an installer requires a login,
licence portal, customer-specific URL, or other access Patched will not have.**
*Answer type: repeating table - Vendor/product | Platform/architecture |
Deployed version | Seats | Business owner | Criticality | Installer
source/format | Download access | Update method.*

**F2. Is there a case management, practice management, or industry-specific
platform in use (for example a legal case management system, a
FCA-regulated trading platform, a clinical system)?**
*Answer type: free text, or "none".*

**F3. Are any of the applications listed in F1 or F2 business-critical, such
that an update failure or removal would stop work?**
*Answer type: free text listing which, or "none flagged".*

**F4. During an ongoing service, who may ask Patched to assess a newly adopted
application, and who must approve adding it to the organisation's approved
software catalogue?**
*Answer type: name/role for requests + name/role for approval.*

---

## G. Practical access

**G1. Who has the authority to approve installing an assessment agent on
company devices, and is that approval already in place or still pending?**
*Answer type: free text (name/role) + status.*

**G2. Is there a preferred deployment method for the assessment agent (via
existing MDM, a manual install guide, a login script)?**
*Answer type: free text, or "no preference - recommend one".*

**G3. Is there a change freeze, audit period, or other date range in the
next 8 weeks during which installing new software on the estate should be
avoided?**
*Answer type: free text with dates, or "none".*

---

*End of customer-facing section. Everything below this line is internal
only and must not be sent to the customer, included in the form export they
see, or pasted into a quote email.*

---

## Internal only - fee-banding logic

**Not sent to the customer.** This section exists so that whoever prices the
engagement from the completed questionnaire applies the same logic, not a
gut feel that varies quote to quote. The Endpoint Assurance fee starts from
£2,500 (published at patched.im/#offer) and is banded up from there based on the answers
above.

Signals that should move the quote up a band, and why:

- **Estate size beyond the base band** - B1 total device count above
  [specialist input required: confirm the device count that defines the
  base £2,500 band and the step size per additional band]. More devices
  means more instrumentation time and a longer, denser findings section.
- **A large gap between B1 (managed) and B2+B3+B4 (unmanaged/BYOD/contractor)**
  - a large unmanaged tail is itself extra scoping and reporting work, not
  just a bigger number in the same report.
- **Low or no MDM enrolment (C1 yes but C2 low, or C1 no)** - the assessment
  has to establish baseline posture without existing tooling to lean on,
  which is more specialist time than an estate that is already substantially
  enrolled.
- **Regulated status (D1 any of FSA/GSC/TCSP, or D2/D3 yes)** - the report's
  framework-mapping section (report-template.md Section 2) requires more
  care and more specific citation when the customer will actually hand this
  report to a regulator or auditor, versus using it only for internal
  planning.
- **A hard, near-term deadline (D4/D5 within [specialist input required:
  confirm the number of weeks that counts as "near-term" and triggers
  expedited/rush pricing])** - compressing the 2 to 4 week instrumentation
  window against a fixed external date is a scheduling cost, and should be
  priced as one.
- **A large or messy line-of-business application list (F1 many rows, or
  F3 several business-critical apps not on the standard catalogue)** - each
  application not already in the Patched software catalogue is additional
  vetting and onboarding work ahead of instrumentation, not something the
  report absorbs for free.
- **No incumbent MSP (E1 no formal IT support)** - Patched is more likely to
  be the only technical point of contact during the engagement, which is
  more coordination time than working alongside an existing provider who
  already knows the estate.

[specialist input required: confirm actual band boundaries and step
pricing - this section states the logic, not the numbers, and the numbers
above are not decided. Do not quote a specific band figure to a prospect
from this document; quote from the signed order only.]
