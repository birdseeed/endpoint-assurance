blackhole2ch)
    # PAT-464: migrated from formulae.brew.sh to GitHub releases (ExistentialAudio/BlackHole)
    name="BlackHole"
    appName="BlackHole2ch.driver"
    type="pkg"
    packageID="audio.existential.BlackHole2ch"
    targetDir="/Library/Audio/Plug-Ins/HAL"
    archiveName="BlackHole2ch"
    downloadURL=$(downloadURLFromGit ExistentialAudio BlackHole)
    appNewVersion=$(versionFromGit ExistentialAudio BlackHole)
    expectedTeamID="Q5C99V536K"
    blockingProcesses=( "coreaudiod" )
    ;;
