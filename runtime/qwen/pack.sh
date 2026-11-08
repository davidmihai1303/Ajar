#!/usr/bin/env bash
# Build on an online machine. The output is a set of files for a USB drive or a release.
set -euo pipefail
cd "$(dirname "$0")/../.."
source runtime/qwen/versions.env
dest=${1:?Usage: pack.sh EMPTY_OUTPUT_DIRECTORY [VERIFIED_GGUF]}
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)
[[ -z "$(ls -A "$dest")" ]] || { echo "Output directory must be empty" >&2; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
model=${2:-"$stage/$MODEL_FILE"}
if [[ $# -lt 2 ]]; then
    curl --fail --location --retry 3 -o "$model" \
        "https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/resolve/$MODEL_REV/$MODEL_FILE"
fi
actual=$(sha256sum "$model")
[[ ${actual%% *} == "$MODEL_SHA" ]] || { echo "Incorrect model SHA-256" >&2; exit 1; }

docker buildx build --platform linux/amd64 --load -t ajar/app:offline -f backend/Dockerfile .
docker pull --platform linux/amd64 "$LLAMA_IMAGE"
docker tag "$LLAMA_IMAGE" ajar/llama:b12182
setup="$stage/ajar"
mkdir -p "$setup/runtime/qwen" "$setup/licenses"
cp docker-compose.yml compose.qwen.yml README.md .env.example "$setup/"
mkdir "$setup/scanner"
cp scanner/{agent.py,detect.py,guard.py,install.sh,netcheck-nmap,README.md} "$setup/scanner/"
cp runtime/qwen/{model.ini,router.sh,start.sh,verify-gpu.sh,versions.env} "$setup/runtime/qwen/"
cp runtime/qwen/install.sh "$setup/"
cp runtime/qwen/README.md "$setup/OFFLINE.md"
cp runtime/qwen/README.md "$setup/runtime/qwen/"
git rev-parse HEAD > "$setup/source-revision"
curl -fsSL "https://raw.githubusercontent.com/ggml-org/llama.cpp/$LLAMA_REV/LICENSE" -o "$setup/licenses/llama.cpp.txt"
curl -fsSL "https://huggingface.co/Qwen/Qwen3.5-9B/resolve/c202236235762e1c871ad0ccb60c8ee5ba337b9a/LICENSE" -o "$setup/licenses/Qwen.txt"
docker image inspect --format '{{.Id}}' ajar/app:offline ajar/llama:b12182 > "$setup/image-ids"
COPYFILE_DISABLE=1 tar -czf "$dest/ajar-setup.tar.gz" -C "$stage" ajar
docker image save ajar/app:offline ajar/llama:b12182 | split -b 1500m - "$dest/images.part."
split -b 1500m "$model" "$dest/model.part."
(cd "$dest" && sha256sum ajar-setup.tar.gz images.part.* model.part.* > SHA256SUMS)
echo "Offline bundle: $dest"
