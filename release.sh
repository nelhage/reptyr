#!/bin/sh

set -e

version="$1"
changelog="$2"

if [ -z "$version" ]; then
    echo "Usage: $0 [NEW-VERSION]" >&2
    exit 2
fi

{
    cat <<EOF
* ${version} ($(date +"%b %d, %Y"))
 - ${changelog-(add changelog here)}

EOF
    cat ChangeLog
} > ChangeLog.tmp
mv -f ChangeLog.tmp ChangeLog

if ! [ "$changelog" ]; then
    "$EDITOR" ChangeLog
fi

version="$version" perl -i -lape '/^#define REPTYR_VERSION/ && s/".*"/"$ENV{version}"/' reptyr.h

git add ChangeLog reptyr.h

git commit -m "reptyr $version"
git tag "reptyr-$version" -m "reptyr $version" -s
