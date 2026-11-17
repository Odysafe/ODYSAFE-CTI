#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"

legacy=${1:-odysafe-cti}
[ "$(docker inspect --type container --format '{{.State.Status}}' "$legacy")" = exited ] ||
    fail "Stop the legacy container with docker stop $legacy before migration."
[ ! -e "$CTI_STATE_DIR" ] || fail 'The destination already exists. Set CTI_STATE_DIR to an unused absolute path.'

umask 077
mkdir -p "$(dirname "$CTI_STATE_DIR")"
staging=$(mktemp -d "${CTI_STATE_DIR}.migration.XXXXXX")
trap 'rm -rf "$staging"' EXIT
docker cp "$legacy:/opt/odysafe/ODYSAFE-CTI/cti-platform" "$staging/legacy"
docker cp "$legacy:/opt/odysafe/ODYSAFE-CTI/docs" "$staging/docs"

mkdir "$staging/datasets"
for directory in database uploads outputs; do
    if [ -d "$staging/legacy/$directory" ]; then
        mv "$staging/legacy/$directory" "$staging/$directory"
    fi
done
for directory in cache data_shield; do
    if [ -d "$staging/legacy/modules/$directory" ]; then
        mv "$staging/legacy/modules/$directory" "$staging/$directory"
    fi
done
for directory in deepdarkCTI-main Ransomware-Tool-Matrix-main; do
    if [ -d "$staging/legacy/modules/$directory" ]; then
        mv "$staging/legacy/modules/$directory" "$staging/datasets/$directory"
    fi
done
if [ -d "$staging/legacy/data/zettelforge" ]; then
    mv "$staging/legacy/data/zettelforge" "$staging/zettelforge"
fi
[ -s "$staging/database/cti_platform.db" ] || fail 'No legacy SQLite database was found.'
rm -rf "$staging/legacy"
mv -T --no-clobber "$staging" "$CTI_STATE_DIR"
[ ! -d "$staging" ] || fail 'The destination was created during migration.'
printf 'Legacy data copied to %s\n' "$CTI_STATE_DIR"
