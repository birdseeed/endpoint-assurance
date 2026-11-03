chronosync)
    name="ChronoSync"
    type="pkgInDmg"
    # PAT-1322 round 7 / PAT-1385 reconciliation: CS4_Download.dmg ships TWO
    # root .pkg files -- Install.pkg (91 MB) and Remove.pkg (2 MB), both real
    # xar packages (hand-verified against the live DMG, 2026-08-16). Same
    # explicit installer selection as chronoagent above.
    pkgName="Install.pkg"
    releaseURL="https://www.econtechnologies.com/UC/updatecheck.php?prod=ChronoSync&lang=en&plat=mac&os=10.14.1&hw=i64&req=1&vers=#"
    appNewVersion=$(curl -sf $releaseURL | sed -r 's/.*VERSION=([^<]+).*/\1/')
    downloadURL="https://downloads.econtechnologies.com/CS4_Download.dmg"
    expectedTeamID="9U697UM7YX"
    ;;
