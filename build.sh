#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-bin}"
export CGO_ENABLED=0

declare -a targets=(
    "windows legacy (Server 2008 R2+)|go1.20.14|windows|amd64|legacy-amd64|.exe"
    "windows amd64|go|windows|amd64|windows-amd64|.exe"
    "windows arm64|go|windows|arm64|windows-arm64|.exe"
    "linux amd64|go|linux|amd64|linux-amd64|"
    "linux arm64|go|linux|arm64|linux-arm64|"
    "darwin amd64|go|darwin|amd64|darwin-amd64|"
    "darwin arm64|go|darwin|arm64|darwin-arm64|"
)

modules=(isolation shell collect kill quarantine sysinfo user-mgmt dns firewall yara hash persistence netconfig log-collect integrity)

for target in "${targets[@]}"; do
    IFS='|' read -r label go_cmd os arch dir ext <<< "$target"
    export GOOS="$os"
    export GOARCH="$arch"
    out_dir="$OUTPUT_DIR/$dir"
    mkdir -p "$out_dir"

    echo
    echo "[$label] -> $out_dir/"

    for mod in "${modules[@]}"; do
        out_file="$out_dir/$mod$ext"
        echo "  $out_file"
        "$go_cmd" build -ldflags="-s -w" -o "$out_file" "./cmd/$mod"
    done
done

echo
echo "Done."
find "$OUTPUT_DIR" -type f | sort | while read -r f; do
    printf '%s\t%s\n' "${f#"$OUTPUT_DIR"/}" "$(wc -c < "$f" | tr -d ' ')"
done
