"""
Static patch-level reference data for the Intune upload funnel (PAT-233).
Best-effort: updated manually when new OS versions ship.
Keep WINDOWS_BUILDS in sync with scanner.py WIN_BUILD when adding entries.
Last reviewed:. Update this file when versions advance.
"""

# Windows build number → (product_slug, version_name)
# Keep in sync with scanner.py WIN_BUILD
WINDOWS_BUILDS = {
    "26100": ("windows_11", "24H2"),
    "22631": ("windows_11", "23H2"),
    "22621": ("windows_11", "22H2"),
    "22000": ("windows_11", "21H2"),
    "19045": ("windows_10", "22H2"),
    "19044": ("windows_10", "21H2"),
    "19043": ("windows_10", "21H1"),
    "19042": ("windows_10", "20H2"),
    "19041": ("windows_10", "2004"),
}

# Latest known build per product line
WINDOWS_LATEST_BUILD = {
    "windows_11": "26100",  # 24H2 — update when next feature update ships
    "windows_10": "19045",  # 22H2
}

MACOS_LATEST = "15.5"   # Sequoia — update for each macOS point release
IOS_LATEST = "18.5"     # Update for each iOS release
ANDROID_LATEST = "15"   # Update for each major Android version
