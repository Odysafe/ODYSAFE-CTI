#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"

[ "$#" -eq 1 ] || fail 'Usage: ./tools/restore.sh /path/to/backup.tar.gz'
archive=$(realpath -- "$1")
require_stopped
[ ! -e "$CTI_STATE_DIR" ] || fail 'Use an empty destination path that does not yet exist.'
actual=$(sha256sum "$archive" | cut -d ' ' -f 1)
expected=$(cut -d ' ' -f 1 "$archive.sha256")
[ "$actual" = "$expected" ] || fail 'Backup checksum mismatch.'
umask 077
mkdir -p "$(dirname "$CTI_STATE_DIR")"
staging=$(mktemp -d "${CTI_STATE_DIR}.restore.XXXXXX")
trap 'rm -rf "$staging"' EXIT
tar -C "$staging" --no-same-owner --no-same-permissions -xzf "$archive"
[ -s "$staging/database/cti_platform.db" ] || fail 'No CTI database was found in the backup.'
mv -T --no-clobber "$staging" "$CTI_STATE_DIR"
[ ! -d "$staging" ] || fail 'The destination was created during restore.'
