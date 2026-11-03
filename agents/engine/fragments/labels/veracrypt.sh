veracrypt|\
veracrypt-macfuse)
    name="VeraCrypt"
    type="pkgInDmg"
    downloadURL="$(downloadURLFromGit veracrypt VeraCrypt)"
    appNewVersion="$(versionFromGit veracrypt VeraCrypt)"
    # PAT-1282: expected_team_id corrected from the stale Installomator-
    # import value Z933746L2S to HLTN5GLG99 (Mounir Joseph IDRASSI), the
    # real signer of the live VeraCrypt .dmg -- confirmed independently
    # three times: two live verifier runs against the actual downloaded
    # artifact (notarization: pass, observed HLTN5GLG99) and one
    # pkgutil --check-signature cross-check during PAT-1283 against the
    # sibling veracrypt-fuse-t artifact from the same maintainer. This
    # shell stanza never received the matching update -- PAT-1429 closes
    # that gap.
    expectedTeamID="HLTN5GLG99"
    ;;
