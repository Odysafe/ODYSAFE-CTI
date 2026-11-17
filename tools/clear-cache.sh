#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"

clear_derived_data() {
    directory=$1
    [ -d "$directory" ] || return 0
    rm -f -- "$directory/deepdarkcti_cache.json" "$directory/deepdarkcti_categories_cache.json" \
        "$directory/rtm_cache.json" "$directory/rtm_categories_cache.json" \
        "$directory/data_shield_cache.json"
    # Old installations may only have the JSON copy of the annotation dataset.
    if [ -s "$directory/apt_annotations.xml" ]; then
        rm -f -- "$directory/apt_annotations_cache.json"
    fi
}

if [ -d "$CTI_STATE_DIR/cache" ]; then
    require_stopped
    clear_derived_data "$CTI_STATE_DIR/cache"
fi

if [ -d "$CTI_ROOT/cti-platform" ]; then
    clear_derived_data "$CTI_ROOT/cti-platform/modules/cache"
    find "$CTI_ROOT/cti-platform" -type d -name __pycache__ -prune -exec rm -rf -- {} +
fi
printf '%s\n' 'Regenerable CTI caches cleared.'
