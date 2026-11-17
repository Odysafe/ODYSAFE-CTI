#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"

[ "$#" -eq 1 ] || fail 'Usage: ./tools/package-offline.sh /path/to/odysafe-cti-VERSION-linux-amd64.tar.gz'
archive=$(realpath -m -- "$1")
[ ! -e "$archive" ] && [ ! -e "$archive.sha256" ] || fail 'The release output already exists.'
image_id=$(docker image inspect --format '{{.Id}}' "$CTI_IMAGE")
[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$CTI_IMAGE")" = linux/amd64 ] ||
    fail 'The release image must target linux/amd64.'

staging=$(mktemp -d "$(dirname "$archive")/.cti-release.XXXXXX")
trap 'rm -rf "$staging"' EXIT
bundle=$staging/odysafe-cti
mkdir -p "$bundle/tools" "$bundle/docs" "$bundle/scripts"
for file in compose.yaml release-images.env start.dh stop README.md LICENSE COPYING; do
    cp "$CTI_ROOT/$file" "$bundle/"
done
for file in common.sh status.sh logs.sh backup.sh restore.sh migrate-legacy.sh prepare-memory.sh clear-cache.sh; do
    cp "$CTI_ROOT/tools/$file" "$bundle/tools/"
done
cp -R "$CTI_ROOT/docs/images" "$bundle/docs/"
cp "$CTI_ROOT/docs/"*.md "$bundle/docs/"
cp "$CTI_ROOT/scripts/pinned_sources.json" "$bundle/scripts/"
# Keep the build and application sources together with the image release.
(
    cd "$CTI_ROOT"
    git ls-files -z -- cti-platform scripts install.sh start.sh uninstall.sh LICENSE COPYING > "$staging/source-files"
    printf '%s\0' Dockerfile .dockerignore compose.yaml docker/entrypoint.sh release-images.env \
        README.md start.dh stop tools/*.sh docs/*.md cti-platform/local_relay.py \
        cti-platform/static/js/i18n-catalog.js cti-platform/static/js/i18n.js >> "$staging/source-files"
    sort -zu -o "$staging/source-files" "$staging/source-files"
    tar -czf "$bundle/source.tar.gz" --null -T "$staging/source-files"
)
docker image save --output "$bundle/images.tar" "$CTI_IMAGE"
printf '%s\n' "$image_id" > "$bundle/image.id"
printf 'Platform: linux/amd64\nImage: %s\nImage ID: %s\n' "$CTI_IMAGE" "$image_id" > "$bundle/distribution.txt"
(cd "$bundle" && sha256sum images.tar > images.tar.sha256)
tar -C "$staging" -czf "$staging/release.tar.gz" odysafe-cti
ln -- "$staging/release.tar.gz" "$archive"
(cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")") > "$archive.sha256"
