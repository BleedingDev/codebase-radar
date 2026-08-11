#!/bin/sh

set -efu

control_root=/var/www/.zerops/analyzer-control
test "$RADAR_ANALYZER_CONTROL_ROOT" = "$control_root"
test "$control_root" != "$RADAR_ANALYZER_ROOT"
test "$control_root" != /var/www/.zerops/radar-cli
test -d "$control_root"
test ! -L "$control_root"
test "$(/usr/bin/realpath "$control_root")" = "$control_root"
sudo /bin/chown root:root -- "$control_root"
sudo /bin/chmod 0555 -- "$control_root"
test "$(/usr/bin/stat -c '%u:%g:%a' "$control_root")" = 0:0:555

set -- "$control_root"/* "$control_root"/.[!.]* "$control_root"/..?*
entry_count=0
for entry in "$@"; do
  if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then
    continue
  fi
  entry_count=$((entry_count + 1))
  case "$entry" in
    "$control_root/runtime-snapshot-loader.mjs" | \
      "$control_root/resource-governance-launcher.mjs")
      expected_mode=444
      ;;
    "$control_root/runtime-memfd-addon.node")
      expected_mode=555
      ;;
    *) exit 1 ;;
  esac
  test -f "$entry"
  test ! -L "$entry"
  sudo /bin/chown root:root -- "$entry"
  sudo /bin/chmod "$expected_mode" -- "$entry"
  test "$(/usr/bin/stat -c '%u:%g:%a:%h' "$entry")" = \
    "0:0:$expected_mode:1"
done
test "$entry_count" = 3
