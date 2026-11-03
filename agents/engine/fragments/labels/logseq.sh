logseq)
    name="Logseq"
    type="dmg"
    if [[ $(arch) == "arm64" ]]; then
        archiveName="darwin-arm64-[0-9.]*.dmg"
        downloadURL=$(downloadURLFromGit logseq logseq)
    elif [[ $(arch) == "i386" ]]; then
        archiveName="darwin-x64-[0-9.]*.dmg"
        downloadURL=$(downloadURLFromGit logseq logseq)
    fi
    appNewVersion=$(versionFromGit logseq logseq)
    # PAT-1272: Logseq rotated its Apple signing certificate; the manifest
    # pin (engine/labels/logseq.json) was reviewed and corrected to
    # K378MFWK59, corroborated independently via upstream Installomator
    # issue #3162, commit 381d5a8d, and a byte-for-byte Homebrew cask SHA256
    # match. This shell stanza never received the matching update -- PAT-1429
    # closes that gap. Not a loosened pin: legitimacy was established first.
    expectedTeamID="K378MFWK59"
    ;;
