#!/bin/sh

# This script generates Soledad Debian packages.
#
# When invoking this script, you should pass a git repository URL and the name
# of the branch that contains the code you wish to build the packages from.
#
# The script will clone the given branch from the given repo, as well as the
# main Soledad repo in github which contains the most up-to-date debian
# branch. It will then merge the desired branch into the debian branch and
# build the packages.

if [ $# -ne 2 ]; then
  echo "Usage: ${0} <url> <branch>"
  exit 1
fi

SOLEDAD_MAIN_REPO=git://github.com/leapcode/soledad.git

url=$1
branch=$2
workdir=`mktemp -d`

git clone -b ${branch} ${url} ${workdir}/soledad
export GIT_DIR=${workdir}/soledad/.git
export GIT_WORK_TREE=${workdir}/soledad
git remote add leapcode ${SOLEDAD_MAIN_REPO}
git fetch leapcode
git checkout debian
git merge --no-edit ${branch}
(cd ${workdir}/soledad && debuild -uc -us)
echo "Packages generated in ${workdir}"
