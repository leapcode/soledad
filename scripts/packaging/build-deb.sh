#!/bin/sh

# This script generates a debian package from your current repository tree
# (including modified and unstaged files), using the debian directory from the
# latest debian/platform-X.Y branch.
#
# In order to achieve that, what it does is:
#
#   - copy the current repository into a temporary directory.
#   - find what is the latest "debian/platform-X.Y" branch.
#   - checkout the "debian/" directory from that branch.
#   - update the "debian/changelog" file with dummy information.
#   - run "debuild -uc -us".

debemail="Leap Automatic Deb Builder <deb@leap.se>"
scriptdir=$(dirname "${0}")
gitroot=$(git -C "${scriptdir}" rev-parse --show-toplevel)
deb_branch=$(git -C "${gitroot}"  branch | grep "debian/platform" | sort | tail -n 1 | xargs)
reponame=$(basename "${gitroot}")
tempdir=$(mktemp -d)
targetdir="${tempdir}/${reponame}"

cp -r "${gitroot}" "${tempdir}/${reponame}"
git -C "${targetdir}" checkout "${deb_branch}" -- debian

(cd "${targetdir}" && DEBEMAIL="${debemail}" dch -b "Automatic build.")
(cd "${targetdir}" && debuild -uc -us)

echo "****************************************"
echo "Packages can be found in: ${tempdir}"
ls "${tempdir}"
echo "****************************************"
