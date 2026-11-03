chronoagent)
    name="ChronoAgent"
    type="pkgInDmg"
    # PAT-1322 round 7 / PAT-1385 reconciliation: CA_Mac_Download.dmg ships
    # TWO root .pkg files -- Install.pkg (60 MB) and Remove.pkg (4 MB), both
    # real xar packages (hand-verified against the live DMG, 2026-08-16). The
    # root-unique default refuses to choose between them, so name the
    # installer explicitly, exactly as gpgsuite does for the same shape.
    pkgName="Install.pkg"
    # packageID="com.econtechnologies.preference.chronoagent"
    # versionKey="CFBundleVersion"
    # None of the above can read out the installed version
    releaseURL="https://www.econtechnologies.com/UC/updatecheck.php?prod=ChronoAgent&lang=en&plat=mac&os=10.14.1&hw=i64&req=1&vers=#"
    appNewVersion=$(curl -sf $releaseURL | sed -r 's/.*VERSION=([^<]+).*/\1/')
    downloadURL="https://downloads.econtechnologies.com/CA_Mac_Download.dmg"
    expectedTeamID="9U697UM7YX"
    ;;
