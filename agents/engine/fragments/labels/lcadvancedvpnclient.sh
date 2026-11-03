lcadvancedvpnclient)
    name="LANCOM Advanced VPN Client"
    type="pkgInDmg"
    archiveName="LANCOM Advanced VPN Client.pkg"
    # PAT-1428: the DMG's root contains TWO .pkg files -- this installer
    # and a hazardous "Uninstall.pkg" -- so the implicit root-unique-pkg
    # default cannot choose safely (confirmed against a real mounted DMG).
    # Name the installer explicitly, exactly as chronoagent/chronosync do
    # for the same shape.
    pkgName="LANCOM Advanced VPN Client.pkg"
    appShortVersion=$(curl -fs https://ftp.lancom.de/LANCOM-Releases/LC-VPN-Client/ | grep "macOS"| tail -1 | sed  "s|.*macOS-\(.*\)-Rel.*|\\1|")
    appNewVersion=(`sed 's/./&./1' <<< $appShortVersion`)
    downloadURL=(https://ftp.lancom.de/LANCOM-Releases/LC-VPN-Client/LC-Advanced-VPN-Client-macOS-"${appShortVersion}"-Rel-x86-64.dmg)
    blockingProcesses=( "LANCOM Advanced VPN Client" "ncprwsmac" )
    expectedTeamID="LL3KBL2M3A"
    ;;
