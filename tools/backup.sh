#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"

[ "$#" -eq 1 ] || fail 'Usage: ./tools/backup.sh /path/to/backup.tar.gz'
archive=$(realpath -m -- "$1")
case "$archive" in
    "$CTI_STATE_DIR"/*) fail 'Write the backup outside CTI_STATE_DIR.' ;;
esac
require_stopped
[ -d "$CTI_STATE_DIR" ] || fail 'No CTI data directory found.'
umask 077
temp=$(mktemp "${archive}.XXXXXX")
trap 'rm -f "$temp"' EXIT
tar -C "$CTI_STATE_DIR" -czf "$temp" .
ln -- "$temp" "$archive"
(cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")") > "$archive.sha256"
