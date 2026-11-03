#!/bin/zsh --no-rcs

# settings

# package
pkgname="Installomator"
identifier="com.scriptingosx.${pkgname}"
install_location="/usr/local/Installomator/"
signature="Developer ID Installer: Armin Briegel (JME5BW3F3R)"

# notarization
dev_keychain_label="notary-scriptingosx"

# parse arguments

zparseopts -D -E -a opts r -run s -script p -pkg n -notarize h -help -labels+:=label_args l+:=label_args

if (( ${opts[(I)(-h|--help)]} )); then
  echo "usage: assemble.sh [--script|--pkg|--notarize] [-labels path/to/labels ...] [arguments...]"
  echo
  echo "builds and runs the installomator script from the fragements."
  echo "additional arguments are passed into the Installomator script for testing."
  exit
fi

# ---------------------------------------------------------------------------
# PATCHED HARDENING GUARD (security review H5) — fail closed.
#
# engine/Installomator.sh is the CANONICAL, hardened engine. It carries Patched
# security controls that DO NOT EXIST in engine/fragments/*:
#   - fail-closed empty/missing expectedTeamID  -> cleanupAndExit 60
#   - notarization / spctl assessment failure   -> cleanupAndExit 61
#   - Team ID mismatch                           -> cleanupAndExit 62
#   - assert_https_url (non-https downloadURL)   -> cleanupAndExit 63
#   - PINNED_SHA256 content-hash mismatch        -> cleanupAndExit 64
#   - DEBUG=0 by default (fragments default DEBUG=1, which also disables the
#     root check in arguments.sh)
# The fragments are stale upstream Installomator and contain none of the above.
# Re-assembling from them would produce an UNHARDENED engine and, with
# --script/--pkg, overwrite engine/Installomator.sh with DEBUG=1 and no
# verification gates — silently stripping every control that ships to customer
# endpoints as root.
#
# This tool is therefore REFUSED by default. It remains only as a dev reference
# for label iteration. To run it for throwaway local testing set
# PATCHED_ALLOW_UNHARDENED_ASSEMBLE=1 — the output MUST NEVER be committed over
# engine/Installomator.sh or shipped. CI (ci/test-engine-hardening.zsh) enforces
# that the committed engine keeps DEBUG=0 and all exit-60..64 markers.
# ---------------------------------------------------------------------------
if [[ "${PATCHED_ALLOW_UNHARDENED_ASSEMBLE:-0}" != "1" ]]; then
    echo "ERROR: engine/assemble.sh is disabled (Patched hardening guard)." >&2
    echo "The fragments do NOT contain the Patched fail-closed verification controls;" >&2
    echo "the canonical hardened engine is the committed engine/Installomator.sh." >&2
    echo "Rebuilding from fragments would strip verification (exit 60-64) and re-enable" >&2
    echo "DEBUG=1. Set PATCHED_ALLOW_UNHARDENED_ASSEMBLE=1 ONLY for local throwaway label" >&2
    echo "testing, and NEVER commit or ship the result over engine/Installomator.sh." >&2
    exit 2
fi

# default setting
runScript=1

if (( ${opts[(I)(-s|--script)]} )); then
    runScript=0
    buildScript=1
fi

if (( ${opts[(I)(-p|--pkg)]} )); then
    runScript=0
    buildScript=1
    buildPkg=1
fi

if (( ${opts[(I)(-n|--notarize)]} )); then
    runScript=0
    buildScript=1
    buildPkg=1
    notarizePkg=1
fi

# -r/--run option overrides default setting
if (( ${opts[(I)(-r|--run)]} )); then
    runScript=1
fi



label_flags=( -l --labels )
# array subtraction to remove options text
label_paths=(${label_args:|label_flags})

#setup some folders
script_dir=$(dirname ${0:A})
repo_dir=$(dirname $script_dir)
build_dir="$repo_dir/build"
destination_file="$build_dir/Installomator.sh"
fragments_dir="$repo_dir/fragments"
labels_dir="$fragments_dir/labels"

# add default labels_dir to label_paths
label_paths+=$labels_dir

#echo "label_paths: $label_paths"

fragment_files=( header.sh version.sh functions.sh arguments.sh main.sh )

# check if fragment files exist (and are readable)
for fragment in $fragment_files; do
    if [[ ! -e $fragments_dir/$fragment ]]; then
        echo "# $fragments_dir/$fragment not found!"
        exit 1
    fi
done

if [[ ! -d $labels_dir ]]; then
    echo "# $labels_dir not found!"
    exit 1
fi

# create $build_dir when necessary
mkdir -p $build_dir

# add the header
cat "$fragments_dir/header.sh" > $destination_file

# read the version.txt
version=$(cat "$fragments_dir/version.sh")
versiondate=$(date +%F)
echo "VERSION=\"$version\"" >> $destination_file
echo "VERSIONDATE=\"$versiondate\"" >> $destination_file
echo >> $destination_file

# add the functions.txt
cat "$fragments_dir/functions.sh" >> $destination_file

# add the arguments.txt
cat "$fragments_dir/arguments.sh" >> $destination_file

# all the labels
for lpath in $label_paths; do
    if [[ -d $lpath ]]; then
        cat "$lpath"/*.sh >> $destination_file
    else
        echo "# $lpath not a directory, skipping..."
    fi
done

# add the footer
cat "$fragments_dir/main.sh" >> $destination_file

# set the executable bit
chmod +x $destination_file

# run script with remaining arguments
if [[ $runScript -eq 1 ]]; then
    $destination_file "$@"
    exit_code=$?
fi

# copy the script to root of repo when flag is set
if [[ $buildScript -eq 1 ]]; then
    echo "# copying script to $repo_dir/Installomator.sh"
    cp $destination_file $repo_dir/Installomator.sh
    chmod 755 $repo_dir/Installomator.sh
    # also update Labels.txt
    $repo_dir/Installomator.sh | tail -n +2 > $repo_dir/Labels.txt
fi

# build a pkg when flag is set
if [[ buildPkg -eq 1 ]]; then
    echo "# building installer package"

    tmpfolder=$(mktemp -d)
    payloadfolder="${tmpfolder}/payload"

    # create a projectfolder with a payload folder
    if [[ ! -d "${payloadfolder}" ]]; then
        mkdir -p "${payloadfolder}"
    fi

    # copy the script file
    cp $repo_dir/Installomator.sh ${payloadfolder}
    chmod 755 ${payloadfolder}/Installomator.sh

    # set the DEBUG variable to 0
    sed -i '' -e 's/^DEBUG=1$/DEBUG=0/g' ${payloadfolder}/Installomator.sh

    # build the component package
    pkgpath="${script_dir}/${pkgname}.pkg"

    pkgbuild --root "${payloadfolder}" \
             --identifier "${identifier}" \
             --version "${version}" \
             --install-location "${install_location}" \
             "${pkgpath}"

    # build the product archive

    productpath="${repo_dir}/${pkgname}-${version}.pkg"

    productbuild --package "${pkgpath}" \
                 --version "${version}" \
                 --identifier "${identifier}" \
                 --sign "${signature}" \
                 "${productpath}"

    # clean up project folder
    rm -Rf "${projectfolder}"
    # clean the component pkgname
    rm "$pkgpath"
fi

# notarize when flag is set
if [[ $notarizePkg -eq 1 ]]; then
    # NOTE: notarytool requires Xcode 13

    # upload for notarization
    xcrun notarytool submit "$productpath" --keychain-profile "$dev_keychain_label" --wait

    # staple result
    echo "# Stapling $productpath"
    xcrun stapler staple "$productpath"
fi

exit $exit_code
