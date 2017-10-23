#!/bin/sh

# This script is intended to copy a single HTML documentation page generated
# using sphinx to the leap.se amber repository that builds the website.
#
# Because amber works differently than sphinx, the following modifications are
# made in the sphinx automatically generated single html page:
#
#   - Remove everything from the start up to "<body>". Amber will take care of
#     adding the HTML template to the top of the file.
#
#   - Remove everything from "</body>" up to "</html>". Amber will take care of
#     adding the HTML template to the end of the file.
#
#   - Remove the navigation div. Amber will take care of adding it's own TOC.
#
#   - Remove the main <h1> tag. Amber adds it automatically.
#
#   - Remove all unicode paragraph characters. They are not hidden by amber and
#     would make the page ugly.
#
#   - Move h2, h3, h4 to one level up (i.e. h1, h2, h3), because amber expects
#     this kind of page organization in order to render TOC and navigation
#     correctly.
#
#   - Turn h5-h7 to simple emphasized paragraphs, otherwise they would be
#     rendered in a huge TOC.
#
#   - Remove the indices and tables from the end of the file, as amber does it
#     by itself.

BASEDIR=$(dirname "$0")

# The following directory structure works well in my filesystem, you might have
# to adapt to your structure/organization.
HEADER=${BASEDIR}/amber-header.txt
SOURCE=${BASEDIR}/../../docs/_build/singlehtml/index.html
TARGET=${BASEDIR}/../../../leap_se/pages/docs/design/soledad.html

cat ${HEADER} > ${TARGET}
cat ${SOURCE} | sed \
  -e '/<!DOCTYPE/,/<body>/d' \
  -e '/role="navigation"/,+5d' \
  -e '/<\/body>/,/<\/html>/d' \
  -e '/<h1>Soledad.*<\/h1>/d' \
  -e 's/¶//g' \
  -e 's/<\(\/\)\?h2>/<\1h1>/g' \
  -e 's/<\(\/\)\?h3>/<\1h2>/g' \
  -e 's/<\(\/\)\?h4>/<\1h3>/g' \
  -e 's/<h[5-7]>\(.*\)<\/h[5-7]>/<p><b>\1<\/b><\/p>/g' \
  -e '/indices-and-tables/,$d' \
    >> ${TARGET}
