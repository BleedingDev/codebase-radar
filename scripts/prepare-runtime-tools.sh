#!/bin/bash
# Trusted preparation entry. It is intentionally invoked only through a clean,
# absolute Bash command supplied by the caller:
# /usr/bin/env -i ... RADAR_RUNTIME_PREP_BOOTSTRAPPED=1 /bin/bash
# --noprofile --norc /absolute/scripts/prepare-runtime-tools.sh /absolute/bin
#
# BASH_ENV can run before this file is read, so direct unsafe invocation is not
# "fixed up" here. Refuse it before any external command instead.

fail() {
  printf '%s\n' "[runtime:$1] $2" >&2
  exit 1
}

if [[ ${RADAR_RUNTIME_PREP_BOOTSTRAPPED-} != '1' ]]; then
  fail 'bootstrap-required' 'Use the clean absolute preparation bootstrap; this script never self-reexecs from an unsafe shell.'
fi
if [[ ${PATH-} != '/usr/bin:/bin' || ${HOME-} != '/nonexistent' || ${LANG-} != 'C.UTF-8' || ${LC_ALL-} != 'C.UTF-8' ]]; then
  fail 'bootstrap-environment-rejected' 'Preparation requires the fixed clean bootstrap environment.'
fi
if [[ ${BASH_ENV+x} || ${ENV+x} || ${NODE_OPTIONS+x} || ${NODE_PATH+x} || ${LD_PRELOAD+x} || ${LD_LIBRARY_PATH+x} ]]; then
  fail 'bootstrap-environment-rejected' 'Preparation refuses inherited shell, loader, preload, or Node path variables.'
fi
while IFS= read -r environment_key; do
  case "$environment_key" in
    DYLD_*|LD_*|NODE_*|BUN_OPTIONS|DENO_*|ESM_LOADER|TSX_*|PYTHON*|RUBYOPT)
      fail 'bootstrap-environment-rejected' "Preparation refuses inherited environment variable $environment_key."
      ;;
  esac
done < <(compgen -e)

set -euo pipefail
IFS=$'\n\t'

if [[ "$#" -ne 1 ]]; then
  fail 'prepare-usage' 'Exactly one runtime bin directory is required.'
fi

path_basename() {
  local path="$1"
  path=${path%/}
  printf '%s\n' "${path##*/}"
}

path_dirname() {
  local path="$1"
  path=${path%/}
  if [[ "$path" == */* ]]; then
    path=${path%/*}
    [[ -n "$path" ]] || path='/'
  else
    path='.'
  fi
  printf '%s\n' "$path"
}

assert_no_symlink_components() {
  local path="$1"
  local remaining
  local component
  local current='/'
  [[ "$path" == /* ]] || fail 'destination-invalid' "Path $path must be absolute."
  remaining=${path#/}
  while [[ -n "$remaining" ]]; do
    component=${remaining%%/*}
    if [[ "$remaining" == */* ]]; then
      remaining=${remaining#*/}
    else
      remaining=''
    fi
    [[ -n "$component" ]] || fail 'destination-invalid' "Path $path has an empty component."
    current="$current$component"
    if [[ -L "$current" ]]; then
      fail 'destination-symlink-rejected' "Destination component $current is a symlink."
    fi
    if [[ ! -e "$current" ]]; then
      fail 'destination-missing' "Destination component $current is missing."
    fi
    current="$current/"
  done
}

assert_regular_no_symlink() {
  local path="$1"
  local link_count
  assert_no_symlink_components "$(path_dirname "$path")"
  if [[ ! -f "$path" || -L "$path" ]]; then
    fail 'control-file-invalid' "Control file $path must be a regular non-symlink file."
  fi
  link_count="$(
    "$trusted_env" -i \
      HOME='/nonexistent' \
      LANG='C.UTF-8' \
      LC_ALL='C.UTF-8' \
      PATH='/usr/bin:/bin' \
      "$trusted_python_bin" -c \
      'import os, sys; print(os.lstat(sys.argv[1]).st_nlink)' \
      "$path"
  )" || fail 'control-file-invalid' "Control file $path metadata could not be authenticated."
  if [[ "$link_count" != '1' ]]; then
    fail 'control-file-invalid' "Control file $path must have exactly one hard link."
  fi
}

script_source="${BASH_SOURCE[0]}"
if [[ "$script_source" != /* || -L "$script_source" || ! -f "$script_source" ]]; then
  fail 'bootstrap-script-invalid' 'The preparation script must be an absolute regular non-symlink file.'
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
if [[ -z "$trusted_realpath" ]]; then
  fail 'trusted-helper-missing' 'A fixed system realpath helper is required.'
fi

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
trusted_python_bin="$(select_trusted_system_executable /usr/bin/python3 /bin/python3 /opt/homebrew/bin/python3 /usr/local/bin/python3)" ||
  fail 'trusted-python-missing' 'A trusted system Python 3 executable is required.'
trusted_curl="$(select_trusted_system_executable /usr/bin/curl /bin/curl /opt/homebrew/bin/curl /usr/local/bin/curl)" ||
  fail 'trusted-helper-missing' 'A trusted system curl executable is required.'
trusted_tar="$(select_trusted_system_executable /usr/bin/tar /bin/tar /opt/homebrew/bin/tar /usr/local/bin/tar)" ||
  fail 'trusted-helper-missing' 'A trusted system tar executable is required.'
trusted_cp="$(select_trusted_system_executable /bin/cp /usr/bin/cp)" ||
  fail 'trusted-helper-missing' 'A trusted system cp executable is required.'
trusted_chmod="$(select_trusted_system_executable /bin/chmod /usr/bin/chmod)" ||
  fail 'trusted-helper-missing' 'A trusted system chmod executable is required.'
trusted_ln="$(select_trusted_system_executable /bin/ln /usr/bin/ln)" ||
  fail 'trusted-helper-missing' 'A trusted system ln executable is required.'
trusted_mkdir="$(select_trusted_system_executable /bin/mkdir /usr/bin/mkdir)" ||
  fail 'trusted-helper-missing' 'A trusted system mkdir executable is required.'
trusted_rm="$(select_trusted_system_executable /bin/rm /usr/bin/rm)" ||
  fail 'trusted-helper-missing' 'A trusted system rm executable is required.'

trusted_verifier="$script_directory/verify-runtime-tools.mjs"
atomic_exchange_helper="$script_directory/runtime-atomic-exchange.py"
assert_regular_no_symlink "$script_source"
assert_regular_no_symlink "$trusted_verifier"
assert_regular_no_symlink "$atomic_exchange_helper"

trusted_node() {
  "$trusted_env" -i \
    HOME='/nonexistent' \
    LANG='C.UTF-8' \
    LC_ALL='C.UTF-8' \
    NO_COLOR='1' \
    PATH='/usr/bin:/bin' \
    RADAR_RUNTIME_BOOTSTRAPPED='1' \
    "$trusted_node_bin" "$trusted_verifier" "$@"
}

trusted_python() {
  "$trusted_env" -i \
    HOME='/nonexistent' \
    LANG='C.UTF-8' \
    LC_ALL='C.UTF-8' \
    NO_COLOR='1' \
    PATH='/usr/bin:/bin' \
    "$trusted_python_bin" -I -S -E "$atomic_exchange_helper" "$@"
}

# This provenance is coupled to manifest.runtimeNode. The trusted verifier
# authenticates the resulting staged byte again before publication; these
# values make a first installation independent of a pre-existing runtime.
pinned_runtime_node_url='https://nodejs.org/dist/v24.18.1/node-v24.18.1-linux-x64.tar.xz'
pinned_runtime_node_archive_sha256='d6c664df3f3f61458e8c277585571328522d705166723a7c7823a9253a4d15a0'
pinned_runtime_node_member='node-v24.18.1-linux-x64/bin/node'
pinned_runtime_node_sha256='f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a'
pinned_runtime_node_archive_max_bytes=$((64 * 1024 * 1024))
pinned_runtime_node_max_bytes=$((256 * 1024 * 1024))
pinned_osv_npm_snapshot_url='https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip?generation=1786418349414076'
pinned_osv_npm_snapshot_sha256='38cb4b8116671e4b0d4c12f2309f180d78c886d1593aef2cb04ff42055fd8e69'
pinned_osv_npm_snapshot_bytes=218758368
pinned_osv_npm_snapshot_path='databases/osv/osv-scalibr/npm/all.zip'
pinned_analyzer_download_max_bytes=$((256 * 1024 * 1024))

calculate_sha256() {
  local file="$1"
  "$trusted_env" -i \
    HOME='/nonexistent' \
    LANG='C.UTF-8' \
    LC_ALL='C.UTF-8' \
    NO_COLOR='1' \
    PATH='/usr/bin:/bin' \
    "$trusted_node_bin" --input-type=module -e \
    "import { createHash } from 'node:crypto'; import { createReadStream } from 'node:fs'; const hash = createHash('sha256'); const stream = createReadStream(process.argv.at(-1), { highWaterMark: 64 * 1024 }); stream.on('data', chunk => hash.update(chunk)); stream.on('error', error => { process.stderr.write(error.message + '\\n'); process.exitCode = 1; }); stream.on('end', () => process.stdout.write(hash.digest('hex')));" \
    -- "$file"
}

verify_sha256() {
  local analyzer_id="$1"
  local expected="$2"
  local file="$3"
  local label="$4"
  local actual
  actual="$(calculate_sha256 "$file")"
  if [[ "$actual" != "$expected" ]]; then
    fail 'checksum-mismatch' "Analyzer $analyzer_id artifact $label expected sha256 $expected; got $actual."
  fi
}

verify_mode_0755() {
  local analyzer_id="$1"
  local file="$2"
  local mode
  mode="$("$trusted_env" -i \
    HOME='/nonexistent' \
    LANG='C.UTF-8' \
    LC_ALL='C.UTF-8' \
    NO_COLOR='1' \
    PATH='/usr/bin:/bin' \
    "$trusted_node_bin" --input-type=module -e \
    "import { lstatSync } from 'node:fs'; process.stdout.write(String(lstatSync(process.argv.at(-1)).mode & 0o7777));" \
    -- "$file")"
  if [[ "$mode" != '493' ]]; then
    fail 'native-mode-invalid' "Analyzer $analyzer_id artifact $file must have mode 0755; got $mode."
  fi
}

verify_bounded_single_link_regular() {
  local label="$1"
  local file="$2"
  local maximum_bytes="$3"
  local size
  size="$(
    "$trusted_env" -i \
      HOME='/nonexistent' \
      LANG='C.UTF-8' \
      LC_ALL='C.UTF-8' \
      NO_COLOR='1' \
      PATH='/usr/bin:/bin' \
      "$trusted_node_bin" --input-type=module -e \
      'import { lstatSync } from "node:fs"; const [path, limit] = process.argv.slice(-2); const metadata = lstatSync(path, { bigint: true }); if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1n || metadata.size < 0n || metadata.size > BigInt(limit)) process.exit(64); process.stdout.write(metadata.size.toString());' \
      -- "$file" "$maximum_bytes"
  )" || fail 'staged-artifact-invalid' "$label must be a bounded single-link regular non-symlink file."
  if [[ ! "$size" =~ ^[0-9]+$ ]]; then
    fail 'staged-artifact-invalid' "$label did not report a canonical byte size."
  fi
}

verify_exact_size() {
  local label="$1"
  local file="$2"
  local expected_bytes="$3"
  local actual_bytes
  actual_bytes="$(
    "$trusted_env" -i \
      HOME='/nonexistent' \
      LANG='C.UTF-8' \
      LC_ALL='C.UTF-8' \
      NO_COLOR='1' \
      PATH='/usr/bin:/bin' \
      "$trusted_node_bin" --input-type=module -e \
      'import { lstatSync } from "node:fs"; process.stdout.write(lstatSync(process.argv.at(-1), { bigint: true }).size.toString());' \
      -- "$file"
  )" || fail 'staged-artifact-invalid' "$label byte length could not be read."
  if [[ "$actual_bytes" != "$expected_bytes" ]]; then
    fail 'staged-artifact-invalid' "$label must contain exactly $expected_bytes bytes; got $actual_bytes."
  fi
}

stage_pinned_runtime_node() {
  local archive="$download_root/runtime-node.tar.xz"
  local archive_listing="$download_root/runtime-node-members.txt"
  local archive_members=()
  local archive_metadata
  local destination="$stage_bin/node"

  if ! "$trusted_curl" \
    --disable \
    --fail \
    --silent \
    --show-error \
    --location \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout 15 \
    --max-time 120 \
    --max-filesize "$pinned_runtime_node_archive_max_bytes" \
    --retry 0 \
    --output "$archive" \
    -- "$pinned_runtime_node_url"; then
    fail 'runtime-node-download-failed' 'The pinned Node archive could not be downloaded.'
  fi
  if [[ ! -f "$archive" || -L "$archive" ]]; then
    fail 'runtime-node-download-invalid' 'The pinned Node download did not produce a regular archive.'
  fi
  verify_bounded_single_link_regular 'Pinned Node archive' "$archive" "$pinned_runtime_node_archive_max_bytes"
  verify_sha256 'runtime-node' "$pinned_runtime_node_archive_sha256" "$archive" 'archive'

  "$trusted_tar" --list --xz --file "$archive" -- "$pinned_runtime_node_member" > "$archive_listing" ||
    fail 'runtime-node-archive-invalid' 'The pinned Node archive member could not be listed.'
  mapfile -t archive_members < "$archive_listing"
  if [[ ${#archive_members[@]} -ne 1 || "${archive_members[0]}" != "$pinned_runtime_node_member" ]]; then
    fail 'runtime-node-archive-invalid' 'The pinned Node archive must expose exactly its reviewed executable member.'
  fi
  archive_metadata="$("$trusted_tar" --list --verbose --numeric-owner --xz --file "$archive" -- "$pinned_runtime_node_member")" ||
    fail 'runtime-node-archive-invalid' 'The pinned Node archive member metadata could not be read.'
  if [[ "${archive_metadata:0:1}" != '-' ]]; then
    fail 'runtime-node-archive-invalid' 'The pinned Node archive member must be a regular file.'
  fi

  if [[ -e "$destination" || -L "$destination" ]]; then
    if [[ ! -f "$destination" || -L "$destination" ]]; then
      fail 'runtime-node-stage-invalid' 'The staged Node destination is not a regular non-symlink file.'
    fi
    "$trusted_rm" -f -- "$destination"
  fi
  "$trusted_tar" \
    --extract \
    --xz \
    --no-same-owner \
    --no-same-permissions \
    --strip-components=2 \
    --directory "$stage_bin" \
    --file "$archive" \
    -- "$pinned_runtime_node_member" ||
    fail 'runtime-node-extraction-invalid' 'The pinned Node executable could not be extracted.'
  if [[ ! -f "$destination" || -L "$destination" ]]; then
    fail 'runtime-node-extraction-invalid' 'The pinned Node extraction did not produce a regular non-symlink executable.'
  fi
  "$trusted_chmod" 0755 -- "$destination"
  verify_bounded_single_link_regular 'Staged runtime Node' "$destination" "$pinned_runtime_node_max_bytes"
  verify_sha256 'runtime-node' "$pinned_runtime_node_sha256" "$destination" 'installed executable'
  verify_mode_0755 'runtime-node' "$destination"
}

stage_semantic_runner() {
  local runner="$stage_bin/radar-semantic-analyzer.mjs"
  if [[ ! -f "$runner" || -L "$runner" ]]; then
    fail 'semantic-runner-stage-invalid' 'The staged semantic runner must be a regular non-symlink file.'
  fi
  "$trusted_chmod" 0755 -- "$runner"
  verify_bounded_single_link_regular 'Staged semantic runner' "$runner" "$pinned_runtime_node_max_bytes"
}

stage_pinned_osv_npm_snapshot() {
  local download="$download_root/osv-npm-all.zip"
  local evidence="$download_root/osv-npm-evidence.json"
  local destination="$stage_root/$pinned_osv_npm_snapshot_path"
  local destination_directory
  destination_directory="$(path_dirname "$destination")"

  if ! "$trusted_curl" \
    --disable \
    --fail \
    --silent \
    --show-error \
    --location \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout 15 \
    --max-time 300 \
    --max-filesize "$pinned_osv_npm_snapshot_bytes" \
    --retry 0 \
    --output "$download" \
    -- "$pinned_osv_npm_snapshot_url"; then
    fail 'osv-snapshot-download-failed' 'The pinned offline OSV npm snapshot could not be downloaded.'
  fi
  verify_bounded_single_link_regular \
    'Pinned offline OSV npm snapshot' \
    "$download" \
    "$pinned_osv_npm_snapshot_bytes"
  verify_exact_size \
    'Pinned offline OSV npm snapshot' \
    "$download" \
    "$pinned_osv_npm_snapshot_bytes"
  verify_sha256 \
    'offline-osv-database' \
    "$pinned_osv_npm_snapshot_sha256" \
    "$download" \
    'raw npm snapshot'

  # Authenticate the validator bytes against the manifest before importing
  # them, regenerate evidence from this exact file, and compare canonically.
  # Evidence is never accepted from a caller or copied into the runtime.
  trusted_node validate-osv-snapshot \
    --runtime-root "$stage_root" \
    --platform linux \
    --architecture x64 \
    --libc glibc \
    --osv-snapshot "$download" > "$evidence"
  verify_bounded_single_link_regular \
    'Generated offline OSV validation evidence' \
    "$evidence" \
    $((64 * 1024))

  if [[ -e "$destination" || -L "$destination" ]]; then
    if [[ ! -f "$destination" || -L "$destination" ]]; then
      fail 'osv-snapshot-stage-invalid' 'The staged offline OSV snapshot destination is not a regular non-symlink file.'
    fi
    "$trusted_rm" -f -- "$destination"
  fi
  local directory
  for directory in \
    "$stage_root/databases" \
    "$stage_root/databases/osv" \
    "$stage_root/databases/osv/osv-scalibr" \
    "$destination_directory"; do
    if [[ -e "$directory" || -L "$directory" ]]; then
      if [[ ! -d "$directory" || -L "$directory" ]]; then
        fail 'osv-snapshot-stage-invalid' 'A staged offline OSV snapshot path component is not a non-symlink directory.'
      fi
    else
      "$trusted_mkdir" -m 0755 -- "$directory"
    fi
  done
  "$trusted_cp" -- "$download" "$destination"
  "$trusted_chmod" 0444 -- "$destination"
  verify_bounded_single_link_regular \
    'Staged offline OSV npm snapshot' \
    "$destination" \
    "$pinned_osv_npm_snapshot_bytes"
  verify_exact_size \
    'Staged offline OSV npm snapshot' \
    "$destination" \
    "$pinned_osv_npm_snapshot_bytes"
  verify_sha256 \
    'offline-osv-database' \
    "$pinned_osv_npm_snapshot_sha256" \
    "$destination" \
    "$pinned_osv_npm_snapshot_path"
}

runtime_bin_input="$1"
if [[ -z "$runtime_bin_input" || "$runtime_bin_input" != /* || "$runtime_bin_input" != "${runtime_bin_input##[[:space:]]}" || "$runtime_bin_input" != "${runtime_bin_input%%[[:space:]]}" || "$runtime_bin_input" =~ [[:cntrl:]] ]]; then
  fail 'destination-invalid' 'Runtime bin directory must be a non-empty absolute path without control characters.'
fi
runtime_bin_lexical="$runtime_bin_input"
case "$runtime_bin_lexical/" in
  *'//'* | *'/../'* | *'/./'*)
    fail 'destination-invalid' 'Runtime bin directory must not contain dot traversal.'
    ;;
esac
if [[ "$(path_basename "$runtime_bin_lexical")" != 'bin' ]]; then
  fail 'destination-invalid' 'Runtime destination must be the managed bin directory.'
fi
if [[ ( -e "$runtime_bin_lexical" || -L "$runtime_bin_lexical" ) && ( ! -d "$runtime_bin_lexical" || -L "$runtime_bin_lexical" ) ]]; then
  fail 'destination-invalid' 'Managed bin destination must be a directory or absent.'
fi

runtime_root_lexical="$(path_dirname "$runtime_bin_lexical")"
assert_no_symlink_components "$runtime_root_lexical"
runtime_root="$(cd -P -- "$runtime_root_lexical" && pwd -P)"
runtime_parent="$(path_dirname "$runtime_root")"
assert_no_symlink_components "$runtime_parent"
journal_path="$runtime_parent/.analyzer-runtime-publish.journal"

for control_file in runtime-manifest.json runtime-manifest.mjs package.json; do
  assert_regular_no_symlink "$runtime_root/$control_file"
done

# A durable stale-generation recovery happens before any new temporary root,
# copy, downloader, archive parser, or verifier can run.
trusted_python recover "$runtime_root" "$journal_path"
trusted_python assert-available "$runtime_parent"

download_root="$(trusted_python fresh-dir "$runtime_parent" '.analyzer-runtime-download.')"
stage_root="$(trusted_python fresh-dir "$runtime_parent" '.analyzer-runtime-stage.')"
if [[ "$download_root" == "$stage_root" || "$(path_dirname "$download_root")" != "$runtime_parent" || "$(path_dirname "$stage_root")" != "$runtime_parent" || -L "$download_root" || -L "$stage_root" ]]; then
  fail 'temporary-root-invalid' 'Preparation temporary roots must be distinct same-parent non-symlink directories.'
fi
plan_file="$download_root/prepare-plan.tsv"

cleanup() {
  local status="$1"
  local recovery_succeeded='1'
  trap - EXIT INT TERM HUP
  if [[ -e "$journal_path" || -L "$journal_path" ]]; then
    if ! trusted_python recover "$runtime_root" "$journal_path"; then
      recovery_succeeded='0'
    fi
  fi
  if [[ "$recovery_succeeded" == '1' && -d "$stage_root" && ! -L "$stage_root" ]]; then
    trusted_python remove-dir "$runtime_parent" "$stage_root" || true
  fi
  if [[ -d "$download_root" && ! -L "$download_root" ]]; then
    trusted_python remove-dir "$runtime_parent" "$download_root" || true
  fi
  exit "$status"
}
trap 'cleanup "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

trusted_node prepare-plan \
  --runtime-root "$runtime_root" \
  --platform linux \
  --architecture x64 \
  --libc glibc > "$plan_file"

# Copy the untrusted candidate source through the same descriptor/no-follow
# boundary used for publication. The helper enforces the reviewed entry,
# depth, per-file, aggregate, link, type, and mutation bounds before any
# undeclared source bytes can consume unbounded staging resources. The final
# verifier still rejects every bounded but undeclared entry before publish.
trusted_python copy-source "$runtime_root" "$stage_root"
stage_bin="$stage_root/bin"
if [[ -e "$stage_bin" || -L "$stage_bin" ]]; then
  if [[ ! -d "$stage_bin" || -L "$stage_bin" ]]; then
    fail 'destination-symlink-rejected' 'Staged managed bin directory is invalid.'
  fi
else
  "$trusted_mkdir" -m 0755 -- "$stage_bin"
fi

# A new deployment starts without bin/node. Acquire its exact reviewed bytes
# into the candidate only, then normalize the source-generated runner there.
stage_pinned_runtime_node
stage_semantic_runner
stage_pinned_osv_npm_snapshot

normalize_managed_launcher() {
  local name="$1"
  local relative_target="$2"
  local launcher_directory="$stage_root/node_modules/.bin"
  local launcher="$launcher_directory/$name"
  local target="$stage_root/node_modules/$relative_target"
  if [[ ! -d "$stage_root/node_modules" || -L "$stage_root/node_modules" ]]; then
    fail 'node-modules-invalid' 'Staged node_modules must be a non-symlink directory.'
  fi
  if [[ ! -d "$launcher_directory" || -L "$launcher_directory" ]]; then
    fail 'launcher-directory-invalid' 'Managed node_modules/.bin must be a non-symlink directory.'
  fi
  if [[ ! -f "$target" || -L "$target" ]]; then
    fail 'launcher-target-invalid' "Managed launcher $name does not have a regular direct target."
  fi
  if [[ -e "$launcher" || -L "$launcher" ]]; then
    if [[ ! -f "$launcher" && ! -L "$launcher" ]]; then
      fail 'launcher-invalid' "Managed launcher $name is not a regular file or symlink."
    fi
    "$trusted_rm" -f -- "$launcher"
  fi
  "$trusted_ln" -s -- "../$relative_target" "$launcher"
  if [[ ! -L "$launcher" ]]; then
    fail 'launcher-invalid' "Managed launcher $name could not be normalized as a symlink."
  fi
}

normalize_managed_launcher 'oxlint' 'oxlint/bin/oxlint'
normalize_managed_launcher 'jscpd' 'jscpd/run-jscpd.js'

fallback_namespace="$stage_root/node_modules/.pnpm/node_modules"
if [[ -e "$fallback_namespace" || -L "$fallback_namespace" ]]; then
  trusted_python remove-dir "$stage_root/node_modules/.pnpm" "$fallback_namespace"
fi

download_verified() {
  local analyzer_id="$1"
  local url="$2"
  local expected_sha256="$3"
  local output="$4"
  if ! "$trusted_curl" \
    --disable \
    --fail \
    --silent \
    --show-error \
    --location \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout 15 \
    --max-time 120 \
    --max-filesize "$pinned_analyzer_download_max_bytes" \
    --retry 0 \
    --output "$output" \
    -- "$url"; then
    fail 'download-failed' "Analyzer $analyzer_id source $url could not be downloaded."
  fi
  if [[ ! -f "$output" || -L "$output" ]]; then
    fail 'download-invalid' "Analyzer $analyzer_id source $url did not produce a regular file."
  fi
  verify_bounded_single_link_regular \
    "Analyzer $analyzer_id download" \
    "$output" \
    "$pinned_analyzer_download_max_bytes"
  verify_sha256 "$analyzer_id" "$expected_sha256" "$output" 'download'
}

validate_plan_record() {
  local analyzer_id="$1"
  local url="$2"
  local source_sha256="$3"
  local download_format="$4"
  local archive_member="$5"
  local output="$6"
  local installed_sha256="$7"
  [[ "$analyzer_id" =~ ^[a-z0-9-]+$ ]] ||
    fail 'manifest-plan-invalid' 'Analyzer id is invalid.'
  [[ "$url" =~ ^https://[^[:space:]#?]+$ ]] ||
    fail 'manifest-plan-invalid' "Analyzer $analyzer_id URL is invalid."
  [[ "$source_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'manifest-plan-invalid' "Analyzer $analyzer_id source checksum is invalid."
  [[ "$installed_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    fail 'manifest-plan-invalid' "Analyzer $analyzer_id installed checksum is invalid."
  [[ "$download_format" == 'raw' || "$download_format" == 'tar.gz' ]] ||
    fail 'manifest-plan-invalid' "Analyzer $analyzer_id format is invalid."
  [[ "$output" == bin/* && "$output" != *'..'* && "$output" != *'//' ]] ||
    fail 'manifest-plan-invalid' "Analyzer $analyzer_id output path is invalid."
  [[ "$(path_basename "$output")" =~ ^[A-Za-z0-9._+-]+$ ]] ||
    fail 'manifest-plan-invalid' "Analyzer $analyzer_id output filename is invalid."
  if [[ "$download_format" == 'raw' ]]; then
    [[ "$archive_member" == '-' ]] ||
      fail 'manifest-plan-invalid' "Analyzer $analyzer_id raw download must not declare an archive member."
  else
    [[ "$archive_member" =~ ^[A-Za-z0-9][A-Za-z0-9._+]*$ && "$archive_member" != '.' && "$archive_member" != '..' ]] ||
      fail 'manifest-plan-invalid' "Analyzer $analyzer_id archive member is invalid."
  fi
}

validate_exact_regular_archive_member() {
  local analyzer_id="$1"
  local archive="$2"
  local expected_member="$3"
  trusted_python validate-tar-gz-member \
    "$archive" \
    "$expected_member" \
    "$pinned_analyzer_download_max_bytes" ||
    fail 'archive-member-invalid' "Analyzer $analyzer_id archive must contain exactly one bounded regular member $expected_member."
}

extract_verified_member() {
  local analyzer_id="$1"
  local archive="$2"
  local expected_member="$3"
  local extraction_root="$4"
  validate_exact_regular_archive_member "$analyzer_id" "$archive" "$expected_member"
  "$trusted_mkdir" -p -- "$extraction_root"
  "$trusted_tar" \
    --extract \
    --gzip \
    --no-same-owner \
    --no-same-permissions \
    --directory "$extraction_root" \
    --file "$archive" \
    -- "$expected_member"
  if [[ ! -f "$extraction_root/$expected_member" || -L "$extraction_root/$expected_member" ]]; then
    fail 'archive-extraction-invalid' "Analyzer $analyzer_id archive member $expected_member did not extract as a regular file."
  fi
}

seen_outputs=()
contains_output() {
  local wanted="$1"
  local actual
  for actual in "${seen_outputs[@]}"; do
    [[ "$actual" == "$wanted" ]] && return 0
  done
  return 1
}

while IFS=$'\t' read -r analyzer_id url source_sha256 download_format archive_member output installed_sha256; do
  [[ -n "$analyzer_id" ]] || continue
  validate_plan_record \
    "$analyzer_id" \
    "$url" \
    "$source_sha256" \
    "$download_format" \
    "$archive_member" \
    "$output" \
    "$installed_sha256"
  if contains_output "$output"; then
    fail 'manifest-plan-invalid' "Duplicate output $output in trusted preparation plan."
  fi
  seen_outputs+=("$output")
  download_path="$download_root/$analyzer_id.download"
  source_path="$download_path"
  download_verified "$analyzer_id" "$url" "$source_sha256" "$download_path"
  if [[ "$download_format" == 'tar.gz' ]]; then
    extraction_root="$download_root/$analyzer_id.extract"
    extract_verified_member \
      "$analyzer_id" \
      "$download_path" \
      "$archive_member" \
      "$extraction_root"
    source_path="$extraction_root/$archive_member"
  fi
  verify_bounded_single_link_regular \
    "Analyzer $analyzer_id installed source" \
    "$source_path" \
    "$pinned_analyzer_download_max_bytes"
  destination_path="$stage_root/$output"
  if [[ "$(path_dirname "$destination_path")" != "$stage_bin" ]]; then
    fail 'destination-invalid' "Analyzer $analyzer_id output escapes staged managed bin directory."
  fi
  if [[ -L "$destination_path" ]]; then
    fail 'destination-symlink-rejected' "Analyzer $analyzer_id staged destination is a symlink."
  fi
  if [[ -e "$destination_path" && ! -f "$destination_path" ]]; then
    fail 'destination-invalid' "Analyzer $analyzer_id staged destination is not a regular file."
  fi
  "$trusted_cp" -- "$source_path" "$destination_path"
  if [[ ! -f "$destination_path" || -L "$destination_path" ]]; then
    fail 'destination-invalid' "Analyzer $analyzer_id did not produce a regular staged destination."
  fi
  "$trusted_chmod" 0755 -- "$destination_path"
  verify_bounded_single_link_regular \
    "Analyzer $analyzer_id staged executable" \
    "$destination_path" \
    "$pinned_analyzer_download_max_bytes"
  verify_sha256 "$analyzer_id" "$installed_sha256" "$destination_path" "$output"
  verify_mode_0755 "$analyzer_id" "$destination_path"
done < "$plan_file"

for expected_output in bin/tracedecay bin/zizmor bin/osv-scanner; do
  if ! contains_output "$expected_output"; then
    fail 'manifest-plan-incomplete' "Trusted preparation plan omitted $expected_output."
  fi
done
if [[ ${#seen_outputs[@]} -ne 3 ]]; then
  fail 'manifest-plan-invalid' 'Trusted preparation plan contains unexpected outputs.'
fi

managed_bin_expected_entries=(
  'node'
  'radar-semantic-analyzer.mjs'
  'tracedecay'
  'zizmor'
  'osv-scanner'
)

is_expected_managed_bin_entry() {
  local candidate="$1"
  local expected
  for expected in "${managed_bin_expected_entries[@]}"; do
    [[ "$candidate" == "$expected" ]] && return 0
  done
  return 1
}

validate_managed_bin_inventory() {
  local entry
  local entry_name
  local expected
  local staged_entries=()

  # Include hidden names too: an unexpected dot file is still an unexpected
  # executable surface. This shell starts with a clean Bash option set.
  shopt -s nullglob dotglob
  staged_entries=("$stage_bin"/*)
  if [[ ${#staged_entries[@]} -ne ${#managed_bin_expected_entries[@]} ]]; then
    fail 'managed-bin-inventory-invalid' 'Staged managed bin has an unexpected number of entries.'
  fi
  for entry in "${staged_entries[@]}"; do
    entry_name="$(path_basename "$entry")"
    if ! is_expected_managed_bin_entry "$entry_name"; then
      fail 'managed-bin-inventory-invalid' "Staged managed bin contains unexpected entry $entry_name."
    fi
    if [[ ! -f "$entry" || -L "$entry" || ! -x "$entry" ]]; then
      fail 'managed-bin-inventory-invalid' "Staged managed bin entry $entry_name must be an executable regular non-symlink file."
    fi
  done
  for expected in "${managed_bin_expected_entries[@]}"; do
    if [[ ! -f "$stage_bin/$expected" || -L "$stage_bin/$expected" || ! -x "$stage_bin/$expected" ]]; then
      fail 'managed-bin-inventory-invalid' "Staged managed bin omitted required executable $expected."
    fi
  done
}

validate_managed_bin_inventory

# The staged runtime must pass the static policy and complete graph identity
# before one durable directory exchange can change the authoritative name.
trusted_node verify \
  --runtime-root "$stage_root" \
  --platform linux \
  --architecture x64 \
  --libc glibc

trusted_python publish "$runtime_root" "$stage_root" "$journal_path"
trusted_python recover "$runtime_root" "$journal_path"
