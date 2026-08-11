#!/bin/sh

set -efu

cgroup_mount=/sys/fs/cgroup
cgroup_root=/sys/fs/cgroup/radar-analysis

has_controller() {
  controls="$(/usr/bin/tr '\n\t' '  ' < "$2")"
  case " $controls " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

test "$RADAR_ANALYSIS_CGROUP_ROOT" = "$cgroup_root"
test -d "$cgroup_mount"
test ! -L "$cgroup_mount"
test "$(/usr/bin/realpath "$cgroup_mount")" = "$cgroup_mount"
test "$(/usr/bin/stat -fc %T "$cgroup_mount")" = cgroup2fs

unified_relative=''
while IFS=: read -r hierarchy controllers relative; do
  if [ "$hierarchy" = 0 ] && [ -z "$controllers" ]; then
    unified_relative="$relative"
    break
  fi
done < /proc/self/cgroup

case "$unified_relative" in
  /) ;;
  /*)
    case "$unified_relative/" in
      *'//'* | *'/./'* | *'/../'*) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac

test "$unified_relative" = /
original_cgroup="$cgroup_mount${unified_relative%/}"
test "$(/usr/bin/realpath "$original_cgroup")" = "$original_cgroup"
test "$original_cgroup/radar-analysis" = "$cgroup_root"
test -f "$original_cgroup/cgroup.procs"
test ! -L "$original_cgroup/cgroup.procs"
test -w "$original_cgroup/cgroup.procs"
test -f "$original_cgroup/cgroup.controllers"
test ! -L "$original_cgroup/cgroup.controllers"
test -f "$original_cgroup/cgroup.subtree_control"
test ! -L "$original_cgroup/cgroup.subtree_control"

for controller in cpu memory pids; do
  has_controller "$controller" "$original_cgroup/cgroup.controllers"
done
printf '%s\n' '+cpu +memory +pids' > "$original_cgroup/cgroup.subtree_control"
for controller in cpu memory pids; do
  has_controller "$controller" "$original_cgroup/cgroup.subtree_control"
done

test ! -e "$cgroup_root"
test ! -L "$cgroup_root"
/bin/mkdir -m 0755 -- "$cgroup_root"
test -d "$cgroup_root"
test ! -L "$cgroup_root"
test "$(/usr/bin/realpath "$cgroup_root")" = "$cgroup_root"
test "$(/usr/bin/stat -c '%u:%g:%a' "$cgroup_root")" = \
  "$(/usr/bin/id -u):$(/usr/bin/id -g):755"
test -f "$cgroup_root/cgroup.controllers"
test ! -L "$cgroup_root/cgroup.controllers"
test -f "$cgroup_root/cgroup.subtree_control"
test ! -L "$cgroup_root/cgroup.subtree_control"

for controller in cpu memory pids; do
  has_controller "$controller" "$cgroup_root/cgroup.controllers"
done
printf '%s\n' '+cpu +memory +pids' > "$cgroup_root/cgroup.subtree_control"
for controller in cpu memory pids; do
  has_controller "$controller" "$cgroup_root/cgroup.subtree_control"
done

for control in cgroup.procs cgroup.kill cgroup.events; do
  test -f "$cgroup_root/$control"
  test ! -L "$cgroup_root/$control"
done
test -w "$cgroup_root/cgroup.procs"
test -w "$cgroup_root/cgroup.kill"

set_control() {
  control_path="$1/$2"
  expected="$3"
  test -f "$control_path"
  test ! -L "$control_path"
  printf '%s\n' "$expected" > "$control_path"
  actual="$(/bin/cat "$control_path")"
  test "$actual" = "$expected"
}

probe="$cgroup_root/radar-init-probe-$$"
test ! -e "$probe"
test ! -L "$probe"
/bin/mkdir -m 0755 -- "$probe"
test -d "$probe"
test ! -L "$probe"
test "$(/usr/bin/realpath "$probe")" = "$probe"
test "$(/usr/bin/stat -c '%u:%g:%a' "$probe")" = \
  "$(/usr/bin/id -u):$(/usr/bin/id -g):755"

set_control "$probe" pids.max 128
set_control "$probe" memory.max 2147483648
set_control "$probe" memory.swap.max 0
set_control "$probe" memory.oom.group 1
set_control "$probe" cpu.max '200000 100000'
test -f "$probe/cgroup.procs"
test ! -L "$probe/cgroup.procs"
test -f "$probe/cgroup.kill"
test ! -L "$probe/cgroup.kill"
test -f "$probe/cgroup.events"
test ! -L "$probe/cgroup.events"

printf '%s\n' "$$" > "$probe/cgroup.procs"
attached="$(/bin/cat "$probe/cgroup.procs")"
case " $attached " in
  *" $$ "*) ;;
  *) exit 1 ;;
esac

printf '%s\n' "$$" > "$original_cgroup/cgroup.procs"
returned="$(/bin/cat "$original_cgroup/cgroup.procs")"
case " $returned " in
  *" $$ "*) ;;
  *) exit 1 ;;
esac

printf '%s\n' 1 > "$probe/cgroup.kill"
attempts=0
while :; do
  events="$(/bin/cat "$probe/cgroup.events")"
  case "$events" in
    *'populated 0'*) break ;;
  esac
  attempts=$((attempts + 1))
  test "$attempts" -lt 50
  /bin/sleep 0.1
done

/bin/rmdir -- "$probe"
test ! -e "$probe"
test ! -L "$probe"
