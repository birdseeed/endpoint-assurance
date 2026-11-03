# NOTE: check minimal macOS requirement
autoload is-at-least

installedOSversion=$(sw_vers -productVersion)
if ! is-at-least 10.14 $installedOSversion; then
    printlog "Installomator requires at least macOS 10.14 Mojave." ERROR
    exit 98
fi


# MARK: argument parsing
if [[ $# -eq 0 ]]; then
    if [[ -z $label ]]; then # check if label is set inside script
        printlog "no label provided, printing labels" REQ
        grep -E '^[a-z0-9\_-]*(\)|\|\\)$' "$0" | tr -d ')|\' | grep -v -E '^(broken.*|longversion|version|valuesfromarguments)$' | sort
        #grep -E '^[a-z0-9\_-]*(\)|\|\\)$' "${labelFile}" | tr -d ')|\' | grep -v -E '^(broken.*|longversion|version|valuesfromarguments)$' | sort
        exit 0
    fi
elif [[ $1 == "/" ]]; then
    # jamf uses sends '/' as the first argument
    printlog "shifting arguments for Jamf" REQ
    shift 3
fi

# first argument is the label
label=$1

# lowercase the label
label=${label:l}

# separate check for 'version' in order to print plain version number without any other information
if [[ $label == "version" ]]; then
    echo "$VERSION"
    exit 0
fi

# ---------------------------------------------------------------------------
# PATCHED — DEAD CODE FOR SHIPPING PURPOSES, DO NOT "FIX" IN PLACE.
#
# This file (and the rest of engine/fragments/*) is stale, pre-hardening
# upstream Installomator. The `eval $1` below is the exact root-privilege
# command-injection construct PAT-1403's rounds 1-3 removed from
# engine/Installomator.sh and engine/fragments/main.sh (see PAT-687 / that
# fix's PATCHED_FIRST_PASS_ARGUMENTS_START block, a few lines up in the
# canonical engine, for the allowlist-checked `typeset -g` replacement).
# It was deliberately NOT ported here, because this file cannot reach a
# customer endpoint:
#   - The ONLY thing that ever reads engine/fragments/* is engine/assemble.sh
#     (and its byte-identical duplicate engine/utils/assemble.sh). Both
#     refuse to run (exit 2) unless PATCHED_ALLOW_UNHARDENED_ASSEMBLE=1 is
#     explicitly set — a pre-existing security-review (H5) guard, predating
#     this ticket, that also states the output must NEVER be committed over
#     engine/Installomator.sh or shipped. ci/test-engine-hardening.zsh
#     (run on every PR touching the engine via .github/workflows/verify-
#     engine.yml) asserts this refusal holds and that the guard leaves the
#     committed engine untouched.
#   - The actual production bundler, tools/build-bundle.sh, copies the
#     committed engine/Installomator.sh directly into the shipped bundle.
#     It never reads engine/fragments/ at all.
# So an engine "rebuilt from fragments" is not a supported build path — it is
# an opt-in, explicitly-gated, throwaway dev/label-iteration tool whose
# output is documented as never leaving the local sandbox. Porting the
# allowlist fix here would be effort spent hardening code that cannot ship;
# instead, if this file is ever wired into a real build/ship path, that
# change must restore the SAME hardening main.sh/Installomator.sh already
# carry before this file's eval can be trusted with real arguments.
# See ci/test_installomator_execution_contract.py's
# test_fragments_arguments_sh_dead_for_shipping_invariants_hold for the
# CI-enforced version of this claim: it fails the moment any of the three
# facts above stop being true, so this comment cannot silently go stale.
# ---------------------------------------------------------------------------
# MARK: reading rest of the arguments
argumentsArray=()
while [[ -n $1 ]]; do
    if [[ $1 =~ ".*\=.*" ]]; then
        # if an argument contains an = character, send it to eval
        printlog "setting variable from argument $1" INFO
        argumentsArray+=( $1 )
        eval $1
    fi
    # shift to next argument
    shift 1
done
printlog "Total items in argumentsArray: ${#argumentsArray[@]}" INFO
printlog "argumentsArray: ${argumentsArray[*]}" INFO

# NOTE: Use proxy for network access if defined
if [[ -n $PROXY ]]; then
    printlog "Proxy defined: $PROXY, testing access to it" REQ
    proxyAddress=$(echo $PROXY | cut -d ":" -f1)
    portNumber=$(echo $PROXY | cut -d ":" -f2)
    printlog "Proxy: $proxyAddress, Port: $portNumber"
    if cmdOutput=$(! nc -z -v -G 10 ${proxyAddress} ${portNumber} 2>&1) ; then
        printlog "$cmdOutput" REQ
        printlog "ERROR : No proxy connection, skipping this." REQ
    else
        printlog "Proxy access detected, so using that." REQ
        export ALL_PROXY="$PROXY"
    fi
fi

# MARK: Logging
log_location="/private/var/log/Installomator.log"

# Check if we're in debug mode, if so then set logging to DEBUG, otherwise default to INFO
# if no log level is specified.
if [[ $DEBUG -ne 0 ]]; then
    LOGGING=DEBUG
elif [[ -z $LOGGING ]]; then
    LOGGING=INFO
    datadogLoggingLevel=INFO
fi

# Associate logging levels with a numerical value so that we are able to identify what
# should be removed. For example if the LOGGING=ERROR only printlog statements with the
# level REQ and ERROR will be displayed. LOGGING=DEBUG will show all printlog statements.
# If a printlog statement has no level set it's automatically assigned INFO.

declare -A levels=(DEBUG 0 INFO 1 WARN 2 ERROR 3 REQ 4)

# If we are able to detect an MDM URL (Jamf Pro) or another identifier for a customer/instance we grab it here, this is useful if we're centrally logging multiple MDM instances.
if [[ -f /Library/Preferences/com.jamfsoftware.jamf.plist ]]; then
    mdmURL=$(defaults read /Library/Preferences/com.jamfsoftware.jamf.plist jss_url)
elif [[ -n "$MDMProfileName" ]]; then
    mdmURL=$(sudo profiles show | grep -A3 "$MDMProfileName" | sed -n -e 's/^.*organization: //p')
else
    mdmURL="Unknown"
fi

# Generate a session key for this run, this is useful to idenify streams when we're centrally logging.
SESSION=$RANDOM

# MARK: START
printlog "################## Start Installomator v. $VERSION, date $VERSIONDATE" REQ
printlog "################## Version: $VERSION" INFO
printlog "################## Date: $VERSIONDATE" INFO
printlog "################## $label" INFO

# Check for DEBUG mode
if [[ $DEBUG -gt 0 ]]; then
    printlog "DEBUG mode $DEBUG enabled." DEBUG
fi

# How we get version number from app
if [[ -z $versionKey ]]; then
    versionKey="CFBundleShortVersionString"
fi

# get current user
currentUser=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ { print $3 }')

# NOTE: check for root
if [[ "$(whoami)" != "root" && "$DEBUG" -eq 0 ]]; then
    # not running as root
    cleanupAndExit 6 "not running as root, exiting" ERROR
fi

# check Swift Dialog presence and version
DIALOG_CMD="/usr/local/bin/dialog"

if [[ ! -x $DIALOG_CMD ]]; then
    # Swift Dialog is not installed, clear cmd file variable to ignore
    printlog "SwiftDialog is not installed, clear cmd file var"
    DIALOG_CMD_FILE=""
fi

# MARK: labels in case statement
pkgPathPattern=""
case $label in
longversion)
    # print the script version
    printlog "Installomater: version $VERSION ($VERSIONDATE)" REQ
    exit 0
    ;;
valuesfromarguments)
    # no action necessary, all values should be provided in arguments
    ;;

# label descriptions start here
