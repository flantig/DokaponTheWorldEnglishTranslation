#!/usr/bin/env bash
set -euo pipefail

if (($# != 2)); then
  printf 'Usage: %s ORIGINAL_ISO NEW_OUTPUT_ISO\n' "$0" >&2
  exit 2
fi
if [[ -e "$2" || -L "$2" ]]; then
  printf 'Output already exists: %s\n' "$2" >&2
  exit 1
fi

tools_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$tools_dir/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/var/tmp}/dokapon-current-build.XXXXXXXX")
trap 'rm -f -- "$work/allocation.iso" "$work/executable.iso" "$work/patcher"; rmdir -- "$work"' EXIT

go -C "$tools_dir" build -o "$work/patcher" .
"$work/patcher" --source "$1" \
  --registry "$project_dir/registry/string-registry.json" \
  --glyphmap "$project_dir/extracted/glyphmap.json" \
  --recipes "$tools_dir/recipes/bootstrap/allocation.json" \
  --recipes "$tools_dir/recipes/code/loader-code.json" \
  --apply --output "$work/allocation.iso"
"$work/patcher" --source "$work/allocation.iso" \
  --recipes "$tools_dir/recipes/build/current/executable.json" \
  --apply --output "$work/executable.iso"
"$work/patcher" --source "$work/executable.iso" \
  --recipes "$tools_dir/recipes/build/current/assets.json" \
  --apply --output "$2"
