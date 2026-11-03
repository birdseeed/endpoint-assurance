# Tier 2 Deploy Catalogue — Coverage Report

Source: `engine/catalogue/deploy-catalogue.json`  
Validator: `ci/validate-catalogue.py`

---

## Summary

| Metric | Count | % |
|---|---|---|
| **Total entries** | 49 | — |
| **Covered** | 44 | 90% |
| **Gaps** | 5 | 10% |

---

## Gap List

| ID | Display Name | Rank | Gap Reason |
|---|---|---|---|
| `cleanmymac` | CleanMyMac | 36 | `no_installomator_label` — not present in the label manifest; macOS-only app requires a new label record |
| `superduper` | SuperDuper! | 39 | `no_installomator_label` — not present in the label manifest; macOS-only app requires a new label record |
| `backblaze` | Backblaze | 40 | `macos_label_pending` — Windows covered via `Backblaze.Backblaze`; macOS requires a new label record |
| `viscosity` | Viscosity | 42 | `windows_winget_unverified` — macOS covered via `viscosity` label; Viscosity for Windows exists but a winget catalog entry has not been confirmed |
| `kindle` | Kindle | 43 | `macos_label_pending` — Windows covered via `Amazon.Kindle`; macOS requires a new label record |

### Gap remediation notes

- **CleanMyMac:** MacPaw distributes CleanMyMac via their CDN (`https://download.macpaw.com/`). Label authoring requires Team ID verification and licensing review (redistribution restrictions may apply).
- **SuperDuper!:** Shirt Pocket distributes SuperDuper via their website. Label authoring is straightforward; no redistribution concerns expected.
- **Backblaze:** Backblaze distributes a macOS installer from `https://www.backblaze.com/mac/install_backblaze.dmg`. Label authoring is straightforward.
- **Viscosity:** Sparklabs publishes Viscosity for Windows at `https://www.sparklabs.com/viscosity/win/`. Check `winget search Viscosity` to confirm catalog presence before adding a winget entry.
- **Kindle:** Amazon distributes Kindle for Mac via `https://www.amazon.com/kindle-dbs/fd/kcp`. Label authoring requires Team ID verification.

---

## Per-Platform Breakdown

### macOS

| Status | Count |
|---|---|
| Has Installomator label | 46 |
| Label is `allowlisted = true` | 6 |
| Label is `installomator_import` (pending review) | 40 |
| No label (gap) | 3 |

**Apps with allowlisted macOS labels (publisher_allowlist):**
zoom, slack, googlechrome, firefox, notion, 1password

**Apps with macOS label pending allowlist review (installomator_import):**
microsoftteams, 1password8, figma, dropbox, vscode, spotify, discord, signal, brave, grammarly, loom, bitwarden, nordvpn, anydesk, teamviewer, malwarebytes, webex, gotomeeting, microsoftedge, microsoftonedrive, microsoftword, microsoftexcel, microsoftpowerpoint, microsoftoutlook, adobeacrobatreader, vlc, rectangle, alfred, hazel, istatmenus, tunnelblick, viscosity, whatsapp, telegram, githubdesktop, sourcetree, tableplus, postman

**Apps with no macOS label (action required):**
cleanmymac, superduper, backblaze

**macOS-only apps (no Windows deploy required):**
rectangle, alfred, cleanmymac, hazel, istatmenus, superduper, tunnelblick, viscosity

### Windows

| Status | Count |
|---|---|
| Has winget ID | 37 |
| Winget verified (winget_community) | 36 |
| No winget — macOS-only platform | 9 |
| Winget pending/unverified | 1 |
| No winget — label pending | 0 |

**macOS-only apps (Windows column is null by design):**
rectangle, alfred, cleanmymac, hazel, istatmenus, superduper, tunnelblick, viscosity

**Windows gap — winget unverified:**
viscosity (Windows client exists; catalog entry unconfirmed)

---

## Allowlist Uplift Candidates

The following macOS labels are `allowlisted = false` but have established, verified winget entries on Windows — meaning they are already trusted cross-platform apps that would benefit from macOS allowlist promotion:

| ID | Label | Winget ID |
|---|---|---|
| figma | figma | Figma.Figma |
| dropbox | dropbox | Dropbox.Dropbox |
| vscode | microsoftvisualstudiocode | Microsoft.VisualStudioCode |
| spotify | spotify | Spotify.Spotify |
| discord | discord | Discord.Discord |
| signal | signal | OpenWhisperSystems.Signal |
| brave | brave | Brave.Brave |
| bitwarden | bitwarden | Bitwarden.Bitwarden |
| anydesk | anydesk | AnyDesk.AnyDesk |
| teamviewer | teamviewer | TeamViewer.TeamViewer |
| microsoftedge | microsoftedge | Microsoft.Edge |
| microsoftonedrive | microsoftonedrive | Microsoft.OneDrive |
| microsoftword | microsoftword | Microsoft.Word |
| microsoftexcel | microsoftexcel | Microsoft.Excel |
| microsoftpowerpoint | microsoftpowerpoint | Microsoft.PowerPoint |
| microsoftoutlook | microsoftoutlook | Microsoft.Outlook |
| vlc | vlc | VideoLAN.VLC |
| githubdesktop | githubdesktop | GitHub.GitHubDesktop |
| sourcetree | sourcetree | Atlassian.Sourcetree |
| tableplus | tableplus | TablePlus.TablePlus |
| postman | postman | Postman.Postman |
| whatsapp | whatsapp | WhatsApp.WhatsApp |
| telegram | telegram | Telegram.TelegramDesktop |

Promoting these to `allowlisted = true` in their label records (after human review) would raise the publisher-allowlisted macOS coverage from 12% (6/49) to 59% (29/49).
