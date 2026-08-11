#!/bin/sh

set -eu

control_root=/build/source/.zerops/analyzer-control
test ! -e "$control_root"
test ! -L "$control_root"
/bin/mkdir -m 0755 -- "$control_root"

for source_target in \
  'packages/analyzer-runtime/runtime-snapshot-loader.mjs:runtime-snapshot-loader.mjs' \
  'packages/analyzer-runtime/control/resource-governance-launcher.mjs:resource-governance-launcher.mjs' \
  'packages/analyzer-runtime/runtime-memfd-addon.node:runtime-memfd-addon.node'; do
  source=${source_target%%:*}
  target=${source_target#*:}
  test -f "/build/source/$source"
  test ! -L "/build/source/$source"
  /bin/cp --no-dereference --preserve=mode -- \
    "/build/source/$source" "$control_root/$target"
  test -f "$control_root/$target"
  test ! -L "$control_root/$target"
  case "$target" in
    runtime-snapshot-loader.mjs | resource-governance-launcher.mjs)
      expected_mode=444
      ;;
    runtime-memfd-addon.node)
      expected_mode=555
      ;;
    *) exit 1 ;;
  esac
  /bin/chmod "$expected_mode" -- "$control_root/$target"
  test "$(/usr/bin/stat -c '%a:%h' "$control_root/$target")" = \
    "$expected_mode:1"
done

set -- "$control_root"/*
test "$#" = 3
test "$1" = "$control_root/resource-governance-launcher.mjs"
test "$2" = "$control_root/runtime-memfd-addon.node"
test "$3" = "$control_root/runtime-snapshot-loader.mjs"
