#!/usr/bin/env bash
# Start the installed bundle. Qwen itself is loaded from the Ask page.
set -euo pipefail
cd "$(dirname "$0")/../.."
export AJAR_UID="$(id -u)" AJAR_GID="$(id -g)"
umask 077
install -d -m 0700 data data/qwen
mkdir -p input models
exec 9>data/qwen/launch.lock
flock 9
if [[ ! -s data/qwen/router.key ]]; then
    python3 -c 'import secrets; print(secrets.token_hex(32))' > data/qwen/router.key.new
    mv data/qwen/router.key.new data/qwen/router.key
fi
compose=(docker compose -f docker-compose.yml -f compose.qwen.yml)
if [[ ! -S data/qwen/router.sock ]]; then echo starting > data/qwen/failure; fi
"${compose[@]}" up -d --no-build --pull never app
if "${compose[@]}" exec -T app python -c 'from netcheck import config; raise SystemExit(not bool(config.LLM_BASE_URL))'; then
    exit 0
fi
source runtime/qwen/versions.env
failure=data/qwen/failure
if [[ ! -s "models/$MODEL_FILE" ]]; then
    "${compose[@]}" stop llama-server
    echo weights > "$failure"
elif ! command -v nvidia-smi >/dev/null || ! nvidia-smi -L | grep -q GPU; then
    "${compose[@]}" stop llama-server
    echo gpu > "$failure"
else
    if ! output=$("${compose[@]}" up -d --no-build --pull never llama-server 2>&1); then
        case "$output" in
            *"port is already allocated"*|*"address already in use"*) echo port > "$failure" ;;
            *"driver"*|*"nvidia"*|*"capabilities"*) echo gpu > "$failure" ;;
            *) echo server > "$failure" ;;
        esac
        echo "$output" >&2
    fi
fi
echo "Ajar: http://127.0.0.1:8001"
