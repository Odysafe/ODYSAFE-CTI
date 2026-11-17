#!/bin/sh
set -eu
. "$(dirname "$0")/common.sh"

[ "$#" -eq 1 ] || fail 'Usage: ./tools/package-data.sh /path/to/odysafe-cti-data-VERSION.tar.gz'
archive=$(realpath -m -- "$1")
[ ! -e "$archive" ] && [ ! -e "$archive.sha256" ] || fail 'The data pack output already exists.'

umask 077
staging=$(mktemp -d "$(dirname "$archive")/.cti-data.XXXXXX")
trap 'rm -rf "$staging"' EXIT
"$CTI_ROOT/tools/prepare-memory.sh" --offline

pack="$staging/odysafe-cti-data"
mkdir -p "$pack/docs" "$pack/model-cache" "$pack/licenses"
mitre_commit=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["mitre_attack"]["commit"])' \
    "$CTI_ROOT/scripts/pinned_sources.json")
mitre_base="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/$mitre_commit"
mitre_version=$(PYTHONPATH="$CTI_ROOT/cti-platform" python3 - "$pack/docs/enterprise-attack.json" <<'PYTHON'
import sys
from pathlib import Path
from modules.mitre_stix_parser import download_enterprise_snapshot

print(download_enterprise_snapshot(Path(sys.argv[1])))
PYTHON
)
curl -fLSs "$mitre_base/LICENSE.txt" -o "$pack/licenses/MITRE-ATTACK.txt"
mitre_sha256=$(sha256sum "$pack/docs/enterprise-attack.json" | cut -d ' ' -f 1)

docker run --rm --pull never --network=none --entrypoint tar "$CTI_IMAGE" \
    -C /opt/cti-bundle -cf - model-cache licenses > "$staging/model.tar"
tar -xf "$staging/model.tar" -C "$pack"
model=nomic-ai/nomic-embed-text-v1.5
revision=$(cat "$pack/model-cache/models--nomic-ai--nomic-embed-text-v1.5/refs/main")
printf 'CTI image: %s\nMITRE ATT&CK Enterprise: %s @ %s\nMITRE ATT&CK SHA-256: %s\nEmbedding model: %s @ %s\n' \
    "$CTI_IMAGE" "$mitre_version" "$mitre_commit" "$mitre_sha256" "$model" "$revision" > "$pack/distribution.txt"

tar -C "$staging" -czf "$staging/data.tar.gz" odysafe-cti-data
ln -- "$staging/data.tar.gz" "$archive"
(cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")") > "$archive.sha256"
