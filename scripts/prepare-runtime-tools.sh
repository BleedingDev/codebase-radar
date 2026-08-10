#!/usr/bin/env bash
set -euo pipefail

runtime_bin="${1:?runtime bin directory is required}"
mkdir -p "$runtime_bin"

download_verified() {
  local url="$1"
  local sha256="$2"
  local output="$3"
  curl --fail --silent --show-error --location "$url" --output "$output"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "$sha256  $output" | shasum --algorithm 256 --check
  else
    echo "$sha256  $output" | sha256sum --check --status
  fi
}

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

download_verified \
  "https://github.com/ScriptedAlchemy/tracedecay/releases/download/v0.0.73/tracedecay-v0.0.73-x86_64-linux.tar.gz" \
  "6a05fee84f503816f50bd1a48d6c7b755c0ded36ac5870561ca95ae7b05a675d" \
  "$scratch/tracedecay.tar.gz"
tar -xzf "$scratch/tracedecay.tar.gz" -C "$runtime_bin" tracedecay

download_verified \
  "https://github.com/zizmorcore/zizmor/releases/download/v1.29.0/zizmor-x86_64-unknown-linux-gnu.tar.gz" \
  "dd96df044a6e8538d5f423790f453bdd03d49e5b2bcc38214acc41a2f1297839" \
  "$scratch/zizmor.tar.gz"
tar -xzf "$scratch/zizmor.tar.gz" -C "$runtime_bin" zizmor

download_verified \
  "https://github.com/google/osv-scanner/releases/download/v2.5.0/osv-scanner_linux_amd64" \
  "edcfc41d257db36148f065055655fe3fcfc434b0b423ea67468a84c207524e0c" \
  "$runtime_bin/osv-scanner"

chmod 0755 "$runtime_bin/tracedecay" "$runtime_bin/zizmor" "$runtime_bin/osv-scanner"
