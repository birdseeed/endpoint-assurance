*)
    # unknown label
    #printlog "unknown label $label"
    cleanupAndExit 1 "unknown label $label" ERROR
    ;;
esac

# MARK: reading arguments again
# >>> PATCHED_REAPPLY_ARGUMENTS_START
# PAT-1403: patchedAllowedArgNames drives the membership test just below —
# on an UNSET or empty array, `${patchedAllowedArgNames[(Ie)$argName]}`
# silently evaluates to 0 ("not found") with no error, so if this array were
# ever renamed, removed, or failed to populate, every override would fall
# through to the non-allowlisted branch and abort with a misleading "not
# allowlisted" error that hides the real cause. Fail loudly and distinctly
# before that can happen.
#
# PAT-1403 (round 2, Finding 3): gated on ${#argumentsArray} > 0 — the
# ORIGINAL round-1 guard fired unconditionally, before the loop, regardless
# of whether there was anything to reapply. That meant a completely normal,
# default install (zero argument overrides on the command line) could be
# aborted with exit 96 too, because the guard could not distinguish "the
# safety array is genuinely broken" from "there was nothing to check this
# invocation" — a zero-argument run never exercises the membership test
# below at all, so there is nothing for the guard to protect in that case.
if (( ${#argumentsArray} > 0 && ${#patchedAllowedArgNames} == 0 )); then
    printlog "PATCHED: FATAL — patchedAllowedArgNames is unset or empty; refusing to reapply runtime argument overrides" ERROR
    cleanupAndExit 96 "patchedAllowedArgNames not populated" ERROR
fi
printlog "Reading arguments again: ${argumentsArray[*]}" INFO
for argument in "${argumentsArray[@]}"; do
    printlog "argument: $argument" DEBUG
    # PAT-1403 (round 2, Finding 8): a token with no '=' at all (e.g. a bare
    # "DEBUG" instead of "DEBUG=1") makes both `${argument%%=*}` and
    # `${argument#*=}` degrade to the identity — argName and argValue would
    # both silently become "DEBUG", i.e. a self-referential DEBUG=DEBUG
    # assignment, instead of being rejected as malformed. Detect and refuse
    # this explicitly rather than let it silently self-assign.
    #
    # PAT-1403 (round 3, Finding 1 — INVESTIGATED, CONFIRMED SAFE): a review
    # raised the concern that upstream's first argument-parsing pass appends
    # EVERY CLI argument to argumentsArray unconditionally, including the
    # bare label name, which would make this guard abort every labeled
    # install. Traced and empirically verified (see the equivalent comment
    # at engine/Installomator.sh's PATCHED_FIRST_PASS_ARGUMENTS_START) that
    # this does NOT apply here: the canonical first pass in
    # engine/Installomator.sh only appends a token to argumentsArray from
    # inside `if [[ $1 == *=* ]]`, and the label is captured into its own
    # `label` variable before that loop runs and is never itself `=`-bearing
    # — so it structurally never reaches argumentsArray. The older,
    # `eval`-based first pass in engine/fragments/arguments.sh (this
    # fragment's own sibling, NOT touched by this ticket — see
    # engine/utils/assemble.sh's hardening guard) has the same property
    # under its own construction: `argumentsArray+=( $1 )` there is likewise
    # gated behind `[[ $1 =~ ".*\=.*" ]]`. This guard therefore cannot fire
    # on a normal label invocation regardless of which first pass produced
    # argumentsArray; it is defense-in-depth, not a live abort path today.
    if [[ "$argument" != *=* ]]; then
        printlog "PATCHED: refusing malformed post-label argument '$argument' (no '=' present)" ERROR
        cleanupAndExit 95 "malformed post-label argument (missing '=')" ERROR
    fi
    argName="${argument%%=*}"
    argValue="${argument#*=}"
    # Reapply the already-allowlisted override after the label stanza without
    # evaluating its value as shell. The label dispatch may set the same
    # variable, but this boundary must remain literal-only.
    if (( ${patchedAllowedArgNames[(Ie)$argName]} )); then
        # PAT-1403: `typeset -g "name=value"` always performs a SCALAR
        # assignment. A label stanza can declare an allowlisted name as an
        # array (e.g. blockingProcesses=( "App A" "App B" )); reapplying a
        # flat CLI value against an already array-typed parameter is a hard
        # zsh runtime error ("inconsistent type for assignment") that aborts
        # the whole script with a bare interpreter message, not ours — and
        # there is no safe, unambiguous way to split a flat CLI value back
        # into array elements (element values can themselves contain spaces,
        # e.g. "1Password Extension Helper"). Refuse loudly and distinctly
        # instead of letting that crash reach the operator unexplained, or
        # silently overwriting the array with a single scalar string that
        # whatever consumes it as an array can no longer read correctly.
        #
        # PAT-1403 (round 2, Finding 4): investigated whether the real
        # endpoint updater ever actually passes a blockingProcesses override
        # — it does not (see the identical comment in engine/Installomator.sh
        # for the full investigation). This refusal is fail-closed-correct
        # and not currently hit in practice, but remains a residual risk for
        # any future caller of this construct.
        if [[ "${(tP)argName}" == array* || "${(tP)argName}" == association* ]]; then
            printlog "PATCHED: refusing array-typed post-label override '$argName' (unsupported)" ERROR
            cleanupAndExit 97 "array-typed argument override not supported" ERROR
        fi
        typeset -g "${argName}=${argValue}"
    else
        printlog "PATCHED: refusing non-allowlisted post-label argument '$argName'" ERROR
        cleanupAndExit 2 "non-allowlisted post-label argument" ERROR
    fi
done
# <<< PATCHED_REAPPLY_ARGUMENTS_END

# verify we have everything we need
if [[ -z $name ]]; then
    printlog "need to provide 'name'" ERROR
    exit 1
fi
if [[ -z $type ]]; then
    printlog "need to provide 'type'" ERROR
    exit 1
fi
if [[ -z $downloadURL ]]; then
    printlog "need to provide 'downloadURL'" ERROR
    exit 1
fi
if [[ -z $expectedTeamID ]]; then
    printlog "need to provide 'expectedTeamID'" ERROR
    exit 1
fi

# Are we only asked to return label name
if [[ $RETURN_LABEL_NAME -eq 1 ]]; then
    printlog "Only returning label name." REQ
    printlog "$name"
    echo "$name"
    exit
fi

# MARK: application download and installation starts here

# Debug output of all variables in a label
printlog "name=${name}" DEBUG
printlog "appName=${appName}" DEBUG
printlog "type=${type}" DEBUG
printlog "archiveName=${archiveName}" DEBUG
printlog "downloadURL=${downloadURL}" DEBUG
printlog "curlOptions=${curlOptions}" DEBUG
printlog "appNewVersion=${appNewVersion}" DEBUG
printlog "appCustomVersion function: $(if type 'appCustomVersion' 2>/dev/null | grep -q 'function'; then echo "Defined. ${appCustomVersion}"; else; echo "Not defined"; fi)" DEBUG
printlog "versionKey=${versionKey}" DEBUG
printlog "packageID=${packageID}" DEBUG
printlog "pkgName=${pkgName}" DEBUG
printlog "choiceChangesXML=${choiceChangesXML}" DEBUG
printlog "expectedTeamID=${expectedTeamID}" DEBUG
printlog "blockingProcesses=${blockingProcesses}" DEBUG
printlog "installerTool=${installerTool}" DEBUG
printlog "CLIInstaller=${CLIInstaller}" DEBUG
printlog "CLIArguments=${CLIArguments}" DEBUG
printlog "updateTool=${updateTool}" DEBUG
printlog "updateToolArguments=${updateToolArguments}" DEBUG
printlog "updateToolRunAsCurrentUser=${updateToolRunAsCurrentUser}" DEBUG
#printlog "Company=${Company}" DEBUG # Not used

# NOTE: Do not disturb active display sleep assertion
if [[ ${INTERRUPT_DND} = "no" ]]; then
    # Check if a fullscreen app is active
    if hasDisplaySleepAssertion; then
        cleanupAndExit 24 "active display sleep assertion detected, aborting" ERROR
    fi
fi

printlog "BLOCKING_PROCESS_ACTION=${BLOCKING_PROCESS_ACTION}"
printlog "NOTIFY=${NOTIFY}"
printlog "LOGGING=${LOGGING}"

# NOTE: Finding LOGO to use in dialogs
case $LOGO in
    appstore)
        # Apple App Store on Mac
        if [[ $(sw_vers -buildVersion) > "19" ]]; then
            LOGO="/System/Applications/App Store.app/Contents/Resources/AppIcon.icns"
        else
            LOGO="/Applications/App Store.app/Contents/Resources/AppIcon.icns"
        fi
        ;;
    jamf)
        # Jamf Pro
        LOGO="/Library/Application Support/JAMF/Jamf.app/Contents/Resources/AppIcon.icns"
        ;;
    mosyleb)
        # Mosyle Business
        LOGO="/Applications/Self-Service.app/Contents/Resources/AppIcon.icns"
        if [[ -z $MDMProfileName ]]; then; MDMProfileName="Mosyle Corporation MDM"; fi
        ;;
    mosylem)
        # Mosyle Manager (education)
        LOGO="/Applications/Manager.app/Contents/Resources/AppIcon.icns"
        if [[ -z $MDMProfileName ]]; then; MDMProfileName="Mosyle Corporation MDM"; fi
        ;;
    addigy)
        # Addigy
        LOGO="/Library/Addigy/macmanage/MacManage.app/Contents/Resources/atom.icns"
        if [[ -z $MDMProfileName ]]; then; MDMProfileName="MDM Profile"; fi
        ;;
    microsoft)
        # Microsoft Endpoint Manager (Intune)
        if [[ -d "/Library/Intune/Microsoft Intune Agent.app" ]]; then
            LOGO="/Library/Intune/Microsoft Intune Agent.app/Contents/Resources/AppIcon.icns"
        elif [[ -d "/Applications/Company Portal.app" ]]; then
            LOGO="/Applications/Company Portal.app/Contents/Resources/AppIcon.icns"
        fi
        if [[ -z $MDMProfileName ]]; then; MDMProfileName="Management Profile"; fi
        ;;
    ws1)
        # Workspace ONE (AirWatch)
        LOGO="/Applications/Workspace ONE Intelligent Hub.app/Contents/Resources/AppIcon.icns"
        if [[ -z $MDMProfileName ]]; then; MDMProfileName="Device Manager"; fi
        ;;
    kandji)
        # Kandji
        LOGO="/Applications/Kandji Self Service.app/Contents/Resources/AppIcon.icns"
        if [[ -z $MDMProfileName ]]; then; MDMProfileName="MDM Profile"; fi
        ;;
    filewave)
        # FileWave
        LOGO="/usr/local/sbin/FileWave.app/Contents/Resources/fwGUI.app/Contents/Resources/kiosk.icns"
        if [[ -z $MDMProfileName ]]; then; MDMProfileName="FileWave MDM Configuration"; fi
        ;;
esac
if [[ ! -a "${LOGO}" ]]; then
    if [[ $(sw_vers -buildVersion) > "19" ]]; then
        LOGO="/System/Applications/App Store.app/Contents/Resources/AppIcon.icns"
    else
        LOGO="/Applications/App Store.app/Contents/Resources/AppIcon.icns"
    fi
fi
printlog "LOGO=${LOGO}" INFO

printlog "Label type: $type" INFO

# NOTE: extract info from data
if [ -z "$archiveName" ]; then
    case $type in
        dmg|pkg|zip|tbz|bz2)
            archiveName="${name}.$type"
            ;;
        pkgInDmg)
            archiveName="${name}.dmg"
            ;;
        *InZip)
            archiveName="${name}.zip"
            ;;
        updateronly)
            ;;
        *)
            printlog "Cannot handle type $type"
            cleanupAndExit 99
            ;;
    esac
fi
printlog "archiveName: $archiveName" INFO

if [ -z "$appName" ]; then
    # when not given derive from name
    appName="$name.app"
fi

if [ -z "$targetDir" ]; then
    case $type in
        dmg|zip|tbz|bz2|app*)
            targetDir="/Applications"
            ;;
        pkg*)
            targetDir="/"
            ;;
        updateronly)
            ;;
        *)
            cleanupAndExit 99 "Cannot handle type $type" ERROR
            ;;
    esac
fi

if [[ -z $blockingProcesses ]]; then
    printlog "no blocking processes defined, using $name as default" INFO
    # PAT-1403: quoted. blockingProcesses is documented (line 70 above) as an
    # array of full process-name strings, one element per name, e.g.
    # blockingProcesses=( "App A" "App B" ) -- a real macOS process can and
    # does have a space in its name (Activity Monitor shows "Google Chrome"
    # as one process, not two). The prior unquoted form here word-split
    # $name before building the array, so any label whose name contains a
    # space (googlechrome: "Google Chrome") silently fell back to checking
    # for processes literally named "Google" and "Chrome" -- neither of
    # which ever exists -- so this default never actually blocked anything
    # for such a label. Found by the PAT-1403 execution contract comparing
    # this fallback's real behaviour against the manifest's declared value.
    blockingProcesses=( "$name" )
fi

# MARK: determine tmp dir
if [ "$DEBUG" -eq 1 ]; then
    # for debugging use script dir as working directory
    tmpDir=$(dirname "$0")
else
    # create temporary working directory
    tmpDir=$(mktemp -d )
fi

# NOTE: change directory to temporary working directory
printlog "Changing directory to $tmpDir" DEBUG
if ! cd "$tmpDir"; then
    cleanupAndExit 13 "error changing directory $tmpDir" ERROR
fi

# MARK: get installed version
getAppVersion
printlog "appversion: $appversion"

# NOTE: Exit if new version is the same as installed version (appNewVersion specified)
if [[ "$type" != "updateronly" && ($INSTALL == "force" || $IGNORE_APP_STORE_APPS == "yes") ]]; then
    printlog "Label is not of type “updateronly”, and it’s set to use force to install or ignoring app store apps, so not using updateTool."
    updateTool=""
fi
if [[ -n $appNewVersion ]]; then
    printlog "Latest version of $name is $appNewVersion"
    if [[ $appversion == $appNewVersion ]]; then
        if [[ $DEBUG -ne 1 ]]; then
            printlog "There is no newer version available."
            if [[ $INSTALL != "force" ]]; then
                message="$name, version $appNewVersion, is the latest version."
                if [[ $currentUser != "loginwindow" && $NOTIFY == "all" ]]; then
                    printlog "notifying"
                    displaynotification "$message" "No update for $name!"
                fi
                if [[ $DIALOG_CMD_FILE != "" ]]; then
                    updateDialog "complete" "Latest version already installed..."
                    sleep 2
                fi
                cleanupAndExit 0 "No newer version." REQ
            fi
        else
            printlog "DEBUG mode 1 enabled, not exiting, but there is no new version of app." WARN
        fi
    fi
else
    printlog "Latest version not specified."
fi

# MARK: check if this is an Update and we can use updateTool
if [[ (-n $appversion && -n "$updateTool") || "$type" == "updateronly" ]]; then
    printlog "App needs to be updated and uses $updateTool. Ignoring BLOCKING_PROCESS_ACTION and running updateTool now."
    updateDialog "wait" "Updating..."

    if [[ $DEBUG -ne 1 ]]; then
        if runUpdateTool; then
            finishing
            cleanupAndExit 0 "updateTool has run" REQ
        elif [[ $type == "updateronly" ]];then
            cleanupAndExit 0 "type is $type so we end here." REQ
        fi # otherwise continue
    else
        printlog "DEBUG mode 1 enabled, not running update tool" WARN
    fi
fi

# MARK: download the archive
if [ -f "$archiveName" ] && [ "$DEBUG" -eq 1 ]; then
    printlog "$archiveName exists and DEBUG mode 1 enabled, skipping download"
else
    # download
    printlog "Downloading $downloadURL to $archiveName" REQ
    if [[ $currentUser != "loginwindow" && $NOTIFY == "all" ]]; then
        printlog "notifying"
        if [[ $updateDetected == "YES" ]]; then
            displaynotification "Downloading $name update" "Download in progress …"
        else
            displaynotification "Downloading new $name" "Download in progress …"
        fi
    fi

    if [[ $DIALOG_CMD_FILE != "" ]]; then
        # pipe
        pipe="$tmpDir/downloadpipe"
        # initialise named pipe for curl output
        initNamedPipe create $pipe

        # run the pipe read in the background
        readDownloadPipe $pipe "$DIALOG_CMD_FILE" & downloadPipePID=$!
        printlog "listening to output of curl with pipe $pipe and command file $DIALOG_CMD_FILE on PID $downloadPipePID" DEBUG

        curlDownload=$(curl -fL -# --show-error ${curlOptions} "$downloadURL" -o "$archiveName" 2>&1 | tee $pipe)
        # because we are tee-ing the output, we want the pipe status of the first command in the chain, not the most recent one
        curlDownloadStatus=$(echo $pipestatus[1])
        killProcess $downloadPipePID

    else
        printlog "No Dialog connection, just download" DEBUG
        curlDownload=$(curl -v -fsL --show-error ${curlOptions} "$downloadURL" -o "$archiveName" 2>&1)
        curlDownloadStatus=$(echo $?)
    fi

    # Trying to detect proxy or web filter on downloaded file
    archiveSHA=$(shasum "$archiveName" | cut -w -f 1)
    archiveSize=$(du -k "$archiveName" | cut -w -f 1)
    archiveType=$(file "$archiveName" | cut -d ':' -f2 )
    printlog "Downloaded $archiveName – Type is $archiveType – SHA is $archiveSHA – Size is $archiveSize kB" INFO

    # Trying to detect download errors, including proxy or web filter blocking on downloaded file
    if [[ $curlDownloadStatus -ne 0 || $archiveType == *ASCII* ]]; then
        printlog "error downloading $downloadURL" ERROR
        message="$name update/installation failed. This will be logged, so IT can follow up."
        if [[ $currentUser != "loginwindow" && $NOTIFY == "all" ]]; then
            printlog "notifying"
            if [[ $updateDetected == "YES" ]]; then
                displaynotification "$message" "Error updating $name"
            else
                displaynotification "$message" "Error installing $name"
            fi
        fi
        if [[ $archiveType == *ASCII* ]]; then
            firstLines=$(head -c 51170 $archiveName)
            deduplicatelogs $firstLines
            cleanupAndExit 2 "File Downloaded is ASCII, we’re probably being blocked by a proxy or filter.  First 5k of file is:\n$logoutput" ERROR
        else
            deduplicatelogs "$curlDownload"
            cleanupAndExit 2 "Error downloading $downloadURL error:\n$logoutput" ERROR
        fi
    fi
fi

# MARK: when user is logged in, and app is running, prompt user to quit app
if [[ $BLOCKING_PROCESS_ACTION == "ignore" ]]; then
    printlog "ignoring blocking processes"
else
    if [[ $currentUser != "loginwindow" ]]; then
        if [[ ${#blockingProcesses} -gt 0 ]]; then
            if [[ ${blockingProcesses[1]} != "NONE" ]]; then
                checkRunningProcesses
            fi
        fi
    fi
fi

# MARK: install the download
printlog "Installing $name" REQ
if [[ $currentUser != "loginwindow" && $NOTIFY == "all" ]]; then
    printlog "notifying"
    if [[ $updateDetected == "YES" ]]; then
        displaynotification "Updating $name" "Installation in progress …"
        updateDialog "wait" "Updating..."
    else
        displaynotification "Installing $name" "Installation in progress …"
        updateDialog "wait" "Installing..."
    fi
fi

if [ -n "$installerTool" ]; then
    # installerTool defined, and we use that for installation
    printlog "installerTool used: $installerTool" REQ
    appName="$installerTool"
fi

case $type in
    dmg)
        installFromDMG
        ;;
    pkg)
        installFromPKG
        ;;
    zip)
        installFromZIP
        ;;
    tbz|bz2)
        installFromTBZ
        ;;
    pkgInDmg)
        installPkgInDmg
        ;;
    pkgInZip)
        installPkgInZip
        ;;
    appInDmgInZip)
        installAppInDmgInZip
        ;;
    *)
        cleanupAndExit 99 "Cannot handle type $type" ERROR
        ;;
esac

updateDialog "wait" "Finishing..."

# MARK: Finishing — print installed application location and version
finishing

# all done!
cleanupAndExit 0 "All done!" REQ
