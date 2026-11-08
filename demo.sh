#!/usr/bin/env bash
# One command for the demo laptop (Linux x86-64, Docker, NVIDIA GPU).
# It prepares whatever is missing (local Qwen weights, the app and llama.cpp images), then starts
# Ajar with the local model from this checkout, the scanner agent, and opens the app.
#
#   ./demo.sh                start (default)
#   ./demo.sh stop           stop the app, Qwen and the scanner agent
#   ./demo.sh status         show what is running
#   ./demo.sh check          backend + scanner tests, Validation Set, gitleaks
#   ./demo.sh update         git pull --ff-only, then start (never after the Test Set upload)
#
# Options for start/update:
#   --browser   open the web page instead of the Ajar desktop app
#   --no-open   do not open anything
#   --rebuild   rebuild the app image even if it matches this commit
#
# It never uses sudo and never scans. The scanner itself (scanner/install.sh) is installed once,
# by hand; this script only checks it. History stays in ./data, the model in ./models (both ignored by git).
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=runtime/qwen/versions.env
source runtime/qwen/versions.env

AJAR_UID=$(id -u) AJAR_GID=$(id -g)
export AJAR_UID AJAR_GID
compose=(docker compose -f docker-compose.yml -f compose.qwen.yml)
app_image=$(sed -n 's/^ *image: *\(ajar\/app:[^ ]*\).*/\1/p' compose.qwen.yml)
llama_image=$(sed -n 's/^ *image: *\(ajar\/llama:[^ ]*\).*/\1/p' compose.qwen.yml)
model="models/$MODEL_FILE"
model_url="https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/$MODEL_REV/$MODEL_FILE"
app_url="http://127.0.0.1:8001/"
agent_port="${NETCHECK_AGENT_PORT:-8765}"
state=data/demo
warnings=()

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m[!] %s\033[0m\n' "$*" >&2; warnings+=("$*"); }
die()  { printf '\033[31m[x] %s\033[0m\n' "$*" >&2; exit 1; }

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------- checks

preflight() {
    [[ $(uname -sm) == "Linux x86_64" ]] || die "This script needs Linux x86-64."
    command -v docker >/dev/null || die "Docker is not installed."
    docker info >/dev/null 2>&1 || die "Docker is not running or this user cannot use it (sudo systemctl start docker; docker group)."
    [[ -n $app_image && -n $llama_image ]] || die "Could not read the image names from compose.qwen.yml."
    install -d -m 0700 data "$state"
    if ! command -v nvidia-smi >/dev/null || ! nvidia-smi -L 2>/dev/null | grep -q GPU; then
        warn "No NVIDIA GPU found: the app works, Ask answers with the built-in texts only."
    fi
    if [[ -f .env ]] && grep -qE '^[[:space:]]*LLM_BASE_URL[[:space:]]*=[[:space:]]*[^[:space:]#]' .env; then
        warn ".env sets LLM_BASE_URL: the app uses that endpoint and the bundled Qwen is not started. Empty it to use the bundled model."
    fi
}

check_scanner() {
    local wrapper=/usr/local/sbin/netcheck-nmap
    if [[ ! -x $wrapper ]]; then
        warn "Live scan is not installed. Once: sudo EXTRA_TCP_PORTS=1883,2323,6379 ./scanner/install.sh"
        return
    fi
    cmp -s scanner/netcheck-nmap "$wrapper" ||
        warn "The installed $wrapper differs from this checkout. Update it: sudo EXTRA_TCP_PORTS=1883,2323,6379 ./scanner/install.sh"
    id -nG | grep -qw netcheck ||
        warn "This shell is not in the netcheck group yet: run 'newgrp netcheck' (or log out and in), then ./demo.sh again."
}

free_gib() { df -P --block-size=1G "$1" | awk 'NR == 2 { print $4 }'; }

need_space() {  # $1 = GiB
    local free
    free=$(free_gib .)
    (( free >= $1 )) || die "Not enough disk space: ${free} GiB free, about $1 GiB needed."
}

# ---------------------------------------------------------------- model

sha_ok() { echo "$MODEL_SHA  $1" | sha256sum --check --status; }

ensure_model() {
    mkdir -p models
    local stamp_file="$state/model.verified"
    if [[ -s $model ]]; then
        # Hashing 5 GB takes a while: verify once and remember the size and time of the verified file.
        if [[ -f $stamp_file && $(<"$stamp_file") == "$(stat -c '%s %Y' "$model")" ]]; then
            say "Qwen weights: ok"
            return
        fi
        say "Verifying the Qwen weights ($MODEL_FILE)"
        if sha_ok "$model"; then
            stat -c '%s %Y' "$model" > "$stamp_file"
            return
        fi
        warn "The weights in $model have the wrong SHA-256; moved to $model.invalid."
        mv "$model" "$model.invalid"
    fi

    local candidate tmp
    shopt -s nullglob
    for candidate in ${AJAR_MODEL:+"$AJAR_MODEL"} "$HOME/models/$MODEL_FILE" "$HOME"/ajar-*/ajar/models/"$MODEL_FILE" \
                     "$HOME/Downloads/$MODEL_FILE"; do
        [[ -s $candidate ]] || continue
        say "Checking $candidate"
        sha_ok "$candidate" || { echo "    wrong SHA-256, skipped"; continue; }
        tmp="models/.$MODEL_FILE.tmp"
        rm -f "$tmp"
        ln "$candidate" "$tmp" 2>/dev/null || { need_space 7; cp "$candidate" "$tmp"; }
        mv "$tmp" "$model"
        stat -c '%s %Y' "$model" > "$stamp_file"
        say "Qwen weights: reused $candidate"
        shopt -u nullglob
        return
    done
    shopt -u nullglob

    say "Downloading the Qwen weights (about 5.3 GB)"
    need_space 7
    curl --fail --location --retry 3 --continue-at - -o "$model.part" "$model_url" ||
        die "The download failed. Run ./demo.sh again to resume it, or put $MODEL_FILE in ~/models."
    sha_ok "$model.part" || { rm -f "$model.part"; die "The downloaded weights have the wrong SHA-256."; }
    mv "$model.part" "$model"
    stat -c '%s %Y' "$model" > "$stamp_file"
}

# ---------------------------------------------------------------- images

ensure_images() {
    if ! docker image inspect "$llama_image" >/dev/null 2>&1; then
        say "Downloading the llama.cpp CUDA image"
        need_space 8
        docker pull --platform linux/amd64 "$LLAMA_IMAGE"
        docker tag "$LLAMA_IMAGE" "$llama_image"
    fi

    local rev built
    rev=$(git rev-parse HEAD 2>/dev/null || echo unknown)
    if [[ -n $(git status --porcelain --untracked-files=no -- backend frontend 2>/dev/null) ]]; then
        rev="$rev-modified"
    fi
    built=$(docker image inspect -f '{{index .Config.Labels "ajar.source"}}' "$app_image" 2>/dev/null || true)
    if [[ $built == "$rev" && $rev != *-modified && ${rebuild:-0} == 0 ]]; then
        say "App image: up to date (${rev:0:7})"
        return
    fi
    say "Building the app image from ${rev:0:7}$([[ $rev == *-modified ]] && echo ' + local changes')"
    if ! docker buildx build --platform linux/amd64 --load --label "ajar.source=$rev" \
            -t "$app_image" -f backend/Dockerfile .; then
        [[ -n $built ]] || die "The app image could not be built."
        warn "The app image could not be rebuilt (offline?). Using the existing one, built from ${built:0:7}."
    fi
}

# ---------------------------------------------------------------- containers

our_project() { "${compose[@]}" config 2>/dev/null | sed -n 's/^name: *//p' | head -n 1; }

stop_other_stacks() {
    # Older offline bundles (e.g. ~/ajar-bundle2) use the same container name and ports.
    local ours ids id project
    ours=$(our_project)
    ids=$( { docker ps -aq --filter name='^netcheck-app$'
             docker ps -q --filter ancestor="$app_image"
             docker ps -q --filter ancestor="$llama_image"; } | sort -u)
    for id in $ids; do
        project=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id" 2>/dev/null || true)
        [[ -n $project && $project == "$ours" ]] && continue
        if [[ -n $project ]]; then
            say "Stopping the other Ajar stack '$project'"
            docker ps -aq --filter label=com.docker.compose.project="$project" | xargs -r docker rm -f >/dev/null
        else
            docker rm -f "$id" >/dev/null 2>&1 || true
        fi
    done
}

check_llm_port() {
    command -v ss >/dev/null || return 0
    local listener
    listener=$(ss -ltnpH 'sport = :8080' 2>/dev/null | grep -v docker-proxy || true)
    if [[ -n $listener ]] && ! docker ps --format '{{.Ports}}' | grep -q '8080->'; then
        warn "Port 8080 is used by another program (a separate llama-server?). Stop it, or Qwen cannot start: $listener"
    fi
}

wait_for_app() {
    local _
    for _ in $(seq 60); do
        curl -fsS -o /dev/null --max-time 2 "$app_url" && return 0
        sleep 1
    done
    die "The app did not answer on $app_url. Logs: ${compose[*]} logs app"
}

qwen_status() {
    local failure
    failure=$(cat data/qwen/failure 2>/dev/null || true)
    case "$failure" in
        weights) warn "Qwen: weights missing or unreadable." ;;
        gpu)     warn "Qwen: the GPU is not available to Docker (NVIDIA Container Toolkit / CDI)." ;;
        port)    warn "Qwen: port 8080 is already in use." ;;
        memory)  warn "Qwen: not enough GPU memory. Close other GPU programs." ;;
        server)  warn "Qwen: the model server did not start. Logs: ${compose[*]} logs llama-server" ;;
        *)       say "Qwen: ready to load (it loads on the first question in Ask)" ;;
    esac
}

# ---------------------------------------------------------------- scanner agent

agent_up() { curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$agent_port/network"; }

our_agent_pid() {
    local pid
    pid=$(cat "$state/agent.pid" 2>/dev/null || true)
    [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null && grep -q 'agent.py' "/proc/$pid/cmdline" 2>/dev/null && echo "$pid"
    return 0
}

stop_agent() {
    local pid
    pid=$(our_agent_pid)
    if [[ -n $pid ]]; then
        kill "$pid"
        say "Scanner agent stopped"
    fi
    rm -f "$state/agent.pid"
}

show_network() {
    local out
    if out=$(python3 scanner/agent.py network 2>&1); then
        python3 -c 'import json, sys
d = json.loads(sys.argv[1])
print("    Wi-Fi %s, %s, subnet %s, gateway %s" % (d.get("ssid") or "(wired / unknown)", d["interface"], d["subnet"], d["gateway"]))' "$out"
    else
        printf '%s\n' "$out" | sed 's/^/    /'
        warn "Network check refused (see above). Live scan stays blocked until the laptop is only on the team hotspot. Importing files works."
    fi
}

start_agent() {
    stop_agent   # always run the agent from this checkout's code
    if agent_up; then
        warn "A scanner agent not started by this script is already on port $agent_port; keeping it."
        return
    fi
    setsid nohup python3 scanner/agent.py serve >>"$state/agent.log" 2>&1 </dev/null &
    echo $! > "$state/agent.pid"
    local _
    for _ in $(seq 10); do agent_up && { say "Scanner agent: running (log: $state/agent.log)"; return; }; sleep 0.5; done
    warn "The scanner agent did not start. Log: $state/agent.log"
}

# ---------------------------------------------------------------- open

open_app() {
    [[ ${open:-desktop} == none ]] && return
    if [[ -z ${DISPLAY:-}${WAYLAND_DISPLAY:-} ]]; then
        echo "    No desktop session: open $app_url yourself."
        return
    fi
    if [[ ${open:-desktop} == desktop ]] && command -v ajar >/dev/null; then
        # Single instance: if Ajar already runs in the tray, this brings its window forward.
        setsid ajar >/dev/null 2>&1 </dev/null &
        say "Opened the Ajar desktop app"
    else
        xdg-open "$app_url" >/dev/null 2>&1 &
        say "Opened $app_url in the browser"
    fi
}

summary() {
    echo
    if [[ ${1:-} == start ]]; then
        say "Ajar: $app_url"
        echo "    Stop everything: ./demo.sh stop"
    fi
    if ((${#warnings[@]})); then
        echo
        printf '\033[33m%d warning(s):\033[0m\n' "${#warnings[@]}"
        printf '  - %s\n' "${warnings[@]}"
    fi
}

# ---------------------------------------------------------------- commands

cmd_start() {
    preflight
    check_scanner
    # Fetch the pinned gitleaks while online, so live check 7 also works offline.
    scripts/gitleaks.sh version >/dev/null 2>&1 ||
        warn "gitleaks could not be downloaded; run scripts/gitleaks.sh once while online."
    ensure_model
    ensure_images
    stop_other_stacks
    check_llm_port
    say "Starting the app and the local model"
    bash runtime/qwen/start.sh
    wait_for_app
    qwen_status
    say "Network"
    show_network
    start_agent
    open_app
    summary start
}

cmd_stop() {
    docker info >/dev/null 2>&1 || die "Docker is not running."
    stop_agent
    stop_other_stacks
    "${compose[@]}" down
    say "Stopped"
}

cmd_status() {
    docker ps --filter name=netcheck-app --filter ancestor="$llama_image" \
        --format 'table {{.Names}}\t{{.Status}}\t{{.Label "com.docker.compose.project"}}' 2>/dev/null || true
    if curl -fsS -o /dev/null --max-time 2 "$app_url"; then echo "App:   running on $app_url"; else echo "App:   not running"; fi
    if agent_up; then echo "Agent: running on 127.0.0.1:$agent_port"; else echo "Agent: not running"; fi
    echo "Qwen:  $(cat data/qwen/failure 2>/dev/null || echo 'not started')"
    echo "Image: built from $(docker image inspect -f '{{index .Config.Labels "ajar.source"}}' "$app_image" 2>/dev/null || echo '(none)'), checkout at $(git rev-parse --short HEAD 2>/dev/null || echo '?')"
}

cmd_check() {
    local failed=0
    docker image inspect "$app_image" >/dev/null 2>&1 || die "No app image yet: run ./demo.sh first."
    say "Backend tests (in the app image, no network)"
    docker run --rm --network none -e HOME=/tmp "$app_image" python -m pytest -q -p no:cacheprovider tests | tail -n 3 || failed=1
    say "Validation Set (must be byte-identical to the official answers)"
    if docker run --rm --network none "$app_image" sh -c '
            netcheck analyze tests/fixtures/validation --out /tmp/v >/dev/null &&
            cmp /tmp/v/findings.csv tests/fixtures/validation/expected_findings.csv &&
            cmp /tmp/v/scores.csv tests/fixtures/validation/expected_scores.csv'; then
        echo "    identical"
    else
        echo "    DIFFERENT"; failed=1
    fi
    say "Scanner tests"
    python3 -m unittest discover -s scanner/tests 2>&1 | tail -n 1 || failed=1
    say "Secrets (gitleaks, whole git history)"
    scripts/gitleaks.sh || failed=1
    say "Working tree"
    if [[ -n $(git status --porcelain --untracked-files=no 2>/dev/null) ]]; then
        warn "Uncommitted changes: the demo runs code that is not in git."
    else
        echo "    clean at $(git rev-parse --short HEAD)"
    fi
    summary
    return "$failed"
}

cmd_update() {
    git pull --ff-only
    cmd_start
}

command=start
open=desktop
rebuild=0
for arg in "$@"; do
    case "$arg" in
        start|stop|status|check|update) command=$arg ;;
        --browser) open=browser ;;
        --no-open) open=none ;;
        --rebuild) rebuild=1 ;;
        -h|--help|help) usage; exit 0 ;;
        *) usage >&2; die "Unknown argument: $arg" ;;
    esac
done
"cmd_$command"
