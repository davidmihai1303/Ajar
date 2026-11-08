#!/usr/bin/env bash
# Extract ajar-setup.tar.gz next to its parts, then run ajar/install.sh as your normal user.
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -sm) == "Linux x86_64" ]] || { echo "This bundle requires Linux x86-64" >&2; exit 1; }
source runtime/qwen/versions.env
parts=$(cd .. && pwd)
verify() { (cd "$parts" && grep "  $1" SHA256SUMS | sha256sum --check --quiet); }
verify 'ajar-setup.tar.gz$'
verify 'images.part.'
cat "$parts"/images.part.* | docker load
docker image inspect --format '{{.Id}}' ajar/app:offline ajar/llama:b12182 | diff - image-ids
mkdir -p models data/qwen
if (cd models && echo "$MODEL_SHA  $MODEL_FILE" | sha256sum --check --status); then
    echo "Qwen weights already verified"
elif verify 'model.part.'; then
    tmp=$(mktemp "models/.qwen.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    cat "$parts"/model.part.* > "$tmp"
    echo "$MODEL_SHA  $tmp" | sha256sum --check --status
    mv "$tmp" "models/$MODEL_FILE"
else
    # Never start an old or corrupt model after a failed verification.
    if [[ -e "models/$MODEL_FILE" ]]; then mv "models/$MODEL_FILE" "models/$MODEL_FILE.invalid"; fi
    echo "Restore the missing or damaged model parts and rerun this installer to enable AI." >&2
fi
bash runtime/qwen/start.sh
