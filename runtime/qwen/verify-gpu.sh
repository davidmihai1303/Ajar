#!/usr/bin/env bash
# Run on the target Linux laptop with other GPU workloads closed.
set -euo pipefail
cd "$(dirname "$0")/../.."
compose=(docker compose -f docker-compose.yml -f compose.qwen.yml)
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sample=$(mktemp)
nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv
nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits -lms 200 > "$sample" &
sampler=$!
trap 'kill "$sampler" 2>/dev/null || true; rm -f "$sample"' EXIT
"${compose[@]}" exec -T app python -m netcheck.explain.smoke --verify-qwen
awk 'NF && $1+0>peak { peak=$1 } END { print "Peak total GPU memory used:",peak,"MiB" }' "$sample"
logs=$("${compose[@]}" logs --no-color --since "$since" llama-server)
printf '%s\n' "$logs" | awk '
  /offloaded [0-9]+\/[0-9]+ layers/ {
    print; match($0, /[0-9]+\/[0-9]+ layers/); split(substr($0, RSTART, RLENGTH), n, "/")
    if (n[1]+0 == n[2]+0 && n[1]+0 > 0) full=1
  }
  /truncated = / { print; if (/truncated = 0/) fit=1; else truncated=1 }
  END { if (!full || !fit || truncated) { print "Could not verify full offload and prompt fit"; exit 1 } }'
