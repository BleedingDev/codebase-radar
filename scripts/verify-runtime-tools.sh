#!/bin/bash
# Public verifier entry. The caller must start this exact absolute file under
# /usr/bin/env -i and /bin/bash --noprofile --norc; BASH_ENV is evaluated before
# this script can run, so unsafe direct invocation is rejected rather than
# re-executed after the fact.

fail() {
  printf '%s\n' "[runtime:$1] $2" >&2
  exit 1
}

if [[ ${RADAR_RUNTIME_VERIFY_BOOTSTRAPPED-} != '1' ]]; then
  fail 'bootstrap-required' 'Use the clean absolute verifier bootstrap; this script never starts Node from an unsafe shell.'
fi
if [[ ${PATH-} != '/usr/bin:/bin' || ${HOME-} != '/nonexistent' || ${LANG-} != 'C.UTF-8' || ${LC_ALL-} != 'C.UTF-8' ]]; then
  fail 'bootstrap-environment-rejected' 'Verifier requires the fixed clean bootstrap environment.'
fi
if [[ ${BASH_ENV+x} || ${ENV+x} || ${NODE_OPTIONS+x} || ${NODE_PATH+x} || ${LD_PRELOAD+x} || ${LD_LIBRARY_PATH+x} ]]; then
  fail 'bootstrap-environment-rejected' 'Verifier refuses inherited shell, loader, preload, or Node path variables.'
fi
while IFS= read -r environment_key; do
  case "$environment_key" in
    DYLD_*|LD_*|NODE_*|BUN_OPTIONS|DENO_*|ESM_LOADER|TSX_*|PYTHON*|RUBYOPT)
      fail 'bootstrap-environment-rejected' "Verifier refuses inherited environment variable $environment_key."
      ;;
  esac
done < <(compgen -e)

set -euo pipefail
IFS=$'\n\t'

path_dirname() {
  local path="$1"
  path=${path%/}
  path=${path%/*}
  [[ -n "$path" ]] || path='/'
  printf '%s\n' "$path"
}

assert_no_symlink_components() {
  local path="$1"
  local remaining
  local component
  local current='/'
  [[ "$path" == /* ]] || fail 'bootstrap-script-invalid' 'Trusted verifier path must be absolute.'
  remaining=${path#/}
  while [[ -n "$remaining" ]]; do
    component=${remaining%%/*}
    if [[ "$remaining" == */* ]]; then
      remaining=${remaining#*/}
    else
      remaining=''
    fi
    [[ -n "$component" ]] || fail 'bootstrap-script-invalid' 'Trusted verifier path has an empty component.'
    current="$current$component"
    [[ ! -L "$current" ]] || fail 'bootstrap-script-invalid' "Trusted verifier component $current is a symlink."
    [[ -e "$current" ]] || fail 'bootstrap-script-invalid' "Trusted verifier component $current is missing."
    current="$current/"
  done
}

script_source="${BASH_SOURCE[0]}"
if [[ "$script_source" != /* || -L "$script_source" || ! -f "$script_source" ]]; then
  fail 'bootstrap-script-invalid' 'The runtime verifier bootstrap must be an absolute regular non-symlink file.'
fi
script_directory="$(path_dirname "$script_source")"
assert_no_symlink_components "$script_directory"
script_directory="$(cd -P -- "$script_directory" && pwd -P)"

trusted_realpath=''
for candidate in /usr/bin/realpath /bin/realpath; do
  if [[ -f "$candidate" && -x "$candidate" && ! -L "$candidate" ]]; then
    trusted_realpath="$candidate"
    break
  fi
done
[[ -n "$trusted_realpath" ]] ||
  fail 'trusted-helper-missing' 'A fixed system realpath helper is required.'

canonical_system_executable() {
  local candidate="$1"
  local canonical
  [[ -f "$candidate" && -x "$candidate" ]] || return 1
  canonical="$("$trusted_realpath" -- "$candidate")" || return 1
  [[ "$canonical" == /* && -f "$canonical" && -x "$canonical" && ! -L "$canonical" ]] || return 1
  case "$candidate" in
    /usr/bin/*) [[ "$canonical" == /usr/bin/* ]] || return 1 ;;
    /bin/*) [[ "$canonical" == /bin/* ]] || return 1 ;;
    /opt/homebrew/bin/*) [[ "$canonical" == /opt/homebrew/* ]] || return 1 ;;
    /usr/local/bin/*) [[ "$canonical" == /usr/local/* ]] || return 1 ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$canonical"
}

select_trusted_system_executable() {
  local candidate
  local canonical
  for candidate in "$@"; do
    if canonical="$(canonical_system_executable "$candidate")"; then
      printf '%s\n' "$canonical"
      return 0
    fi
  done
  return 1
}

trusted_env="$(select_trusted_system_executable /usr/bin/env /bin/env)" ||
  fail 'trusted-helper-missing' 'A trusted system env executable is required.'
trusted_uname="$(select_trusted_system_executable /usr/bin/uname /bin/uname)" ||
  fail 'trusted-helper-missing' 'A trusted system uname executable is required.'
bootstrap_platform="$(
  "$trusted_env" -i \
    HOME='/nonexistent' \
    LANG='C.UTF-8' \
    LC_ALL='C.UTF-8' \
    PATH='/usr/bin:/bin' \
    "$trusted_uname" -s
)" || fail 'trusted-helper-missing' 'The trusted host platform could not be determined.'

# Linux is the production bootstrap path. The deployment caller installs this
# exact interpreter and authenticates its raw ELF before this script runs.
# Darwin's system/Homebrew route below is deliberately development-only and
# must never become a production bootstrap fallback.
case "$bootstrap_platform" in
  Linux)
    trusted_node_bin='/usr/local/lib/radar-node-v24.18.1/bin/node'
    if [[ ! -f "$trusted_node_bin" || ! -x "$trusted_node_bin" || -L "$trusted_node_bin" ]]; then
      fail 'trusted-node-missing' "Production requires $trusted_node_bin."
    fi
    assert_no_symlink_components "$trusted_node_bin"
    canonical_node_path="$("$trusted_realpath" -- "$trusted_node_bin")" ||
      fail 'trusted-node-invalid' "Production Node $trusted_node_bin could not be canonicalized."
    if [[ "$canonical_node_path" != "$trusted_node_bin" ]]; then
      fail 'trusted-node-invalid' "Production Node must be exactly $trusted_node_bin."
    fi
    trusted_node_version="$(
      "$trusted_env" -i \
        HOME='/nonexistent' \
        LANG='C.UTF-8' \
        LC_ALL='C.UTF-8' \
        PATH='/usr/bin:/bin' \
        "$trusted_node_bin" --version
    )" || fail 'trusted-node-version-invalid' "Production Node $trusted_node_bin could not report its version."
    if [[ "$trusted_node_version" != 'v24.18.1' ]]; then
      fail 'trusted-node-version-invalid' "Production Node must report v24.18.1; got $trusted_node_version."
    fi
    ;;
  Darwin)
    # Development-only: production deployments are Linux and must use the
    # exact pinned interpreter above, never a moving system/Homebrew Node.
    trusted_node_bin="$(select_trusted_system_executable /usr/bin/node /bin/node /opt/homebrew/bin/node /usr/local/bin/node)" ||
      fail 'trusted-node-missing' 'A Darwin development Node executable is required.'
    ;;
  *)
    fail 'trusted-node-platform-unsupported' "Unsupported bootstrap platform $bootstrap_platform."
    ;;
esac
verifier="$script_directory/verify-runtime-tools.mjs"
assert_no_symlink_components "$(path_dirname "$verifier")"
if [[ -L "$verifier" || ! -f "$verifier" ]]; then
  fail 'trusted-verifier-invalid' 'The trusted workspace verifier must be a regular non-symlink file.'
fi

assert_single_link_regular() {
  local path="$1"
  local link_count
  link_count="$(
    "$trusted_env" -i \
      HOME='/nonexistent' \
      LANG='C.UTF-8' \
      LC_ALL='C.UTF-8' \
      PATH='/usr/bin:/bin' \
      "$trusted_node_bin" -e \
      'const fs = require("node:fs"); process.stdout.write(String(fs.lstatSync(process.argv[1]).nlink));' \
      "$path"
  )" || fail 'trusted-verifier-invalid' "Trusted file $path metadata could not be authenticated."
  if [[ "$link_count" != '1' ]]; then
    fail 'trusted-verifier-invalid' "Trusted file $path must have exactly one hard link."
  fi
}

assert_single_link_regular "$script_source"
assert_single_link_regular "$verifier"

if [[ ${RADAR_ANALYZER_ROOT+x} ]]; then
  exec "$trusted_env" -i \
    HOME='/nonexistent' \
    LANG='C.UTF-8' \
    LC_ALL='C.UTF-8' \
    NO_COLOR='1' \
    PATH='/usr/bin:/bin' \
    RADAR_RUNTIME_BOOTSTRAPPED='1' \
    RADAR_RUNTIME_VERIFY_BOOTSTRAPPED='1' \
    "RADAR_ANALYZER_ROOT=$RADAR_ANALYZER_ROOT" \
    "$trusted_node_bin" "$verifier" "$@"
fi

exec "$trusted_env" -i \
  HOME='/nonexistent' \
  LANG='C.UTF-8' \
  LC_ALL='C.UTF-8' \
  NO_COLOR='1' \
  PATH='/usr/bin:/bin' \
  RADAR_RUNTIME_BOOTSTRAPPED='1' \
  RADAR_RUNTIME_VERIFY_BOOTSTRAPPED='1' \
  "$trusted_node_bin" "$verifier" "$@"
