# safari.sh — Safari MDM profile compliance signals.
# All 6 signals require an MDM-deployed Safari configuration profile.
# Reads profiles -P -o stdout once; absent keys mean the profile is not deployed (fail).
# Sourced by patched-collect.sh; not executable directly.
#
# macOS 26 note (PAT-706 Layer 2 — needs VM verification):
#   On macOS 26.5.1 the `profiles -P -o stdout` output format may have changed
#   (new key names, XML/JSON plist output, or the command may require different
#   flags).  The grep patterns below matched the legacy text format; if the VM
#   shows all 6 signals returning null after this fix, capture the raw output of
#   `profiles -P -o stdout` (or `profiles list -o stdout`) on the macOS 26 box
#   and update the grep patterns accordingly.  The pre-init defaults in
#   patched-collect.sh ensure the collector always emits valid JSON even if this
#   function cannot determine the correct values.

collect_safari() {
    # Explicit defaults: set before any command runs so that even an early
    # function exit (e.g. profiles command missing or returning unexpected output
    # on macOS 26) leaves these variables bound.  The "No" default is intentionally
    # fail-closed — absent profile key = MDM has not enforced the setting.
    SAFARI_AUTO_OPEN_DOWNLOADS_DISABLED="No"
    SAFARI_FRAUDULENT_WARNING="No"
    SAFARI_CROSS_SITE_TRACKING_BLOCKED="No"
    SAFARI_PRIVATE_MEASUREMENT="No"
    SAFARI_FULL_URL_SHOWN="No"
    SAFARI_STATUS_BAR_SHOWN="No"

    local _PROFILES
    _PROFILES=$(profiles -P -o stdout 2>/dev/null || true)

    # §6.3.1 — Auto-open of safe downloads disabled
    if printf '%s\n' "$_PROFILES" | grep -q 'AutoOpenSafeDownloads = 0'; then
        SAFARI_AUTO_OPEN_DOWNLOADS_DISABLED="Yes"
    else
        SAFARI_AUTO_OPEN_DOWNLOADS_DISABLED="No"
    fi

    # §6.3.3 — Warn about fraudulent websites
    if printf '%s\n' "$_PROFILES" | grep -q 'WarnAboutFraudulentWebsites = 1'; then
        SAFARI_FRAUDULENT_WARNING="Yes"
    else
        SAFARI_FRAUDULENT_WARNING="No"
    fi

    # §6.3.4 — Cross-site tracking prevention (multiple known profile key variants)
    if printf '%s\n' "$_PROFILES" | grep -qE 'WebKitPreferences\.storageBlockingPolicy = 1|WebKitStorageBlockingPolicy = 1|BlockStoragePolicy = 2'; then
        SAFARI_CROSS_SITE_TRACKING_BLOCKED="Yes"
    else
        SAFARI_CROSS_SITE_TRACKING_BLOCKED="No"
    fi

    # §6.3.6 — Private click measurement (advertising privacy protection)
    if printf '%s\n' "$_PROFILES" | grep -q 'WebKitPreferences.privateClickMeasurementEnabled = 1'; then
        SAFARI_PRIVATE_MEASUREMENT="Yes"
    else
        SAFARI_PRIVATE_MEASUREMENT="No"
    fi

    # §6.3.7 — Full URL shown in smart search field
    if printf '%s\n' "$_PROFILES" | grep -q 'ShowFullURLInSmartSearchField = 1'; then
        SAFARI_FULL_URL_SHOWN="Yes"
    else
        SAFARI_FULL_URL_SHOWN="No"
    fi

    # §6.3.10 — Status bar shown
    if printf '%s\n' "$_PROFILES" | grep -q 'ShowOverlayStatusBar = 1'; then
        SAFARI_STATUS_BAR_SHOWN="Yes"
    else
        SAFARI_STATUS_BAR_SHOWN="No"
    fi
}
