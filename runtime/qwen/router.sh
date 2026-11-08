#!/bin/sh
set -eu
umask 077
runtime=/run/ajar-model
if ! test -r /models/Qwen3.5-9B-Q4_K_M.gguf; then
    echo weights > "$runtime/failure"
    exit 1
fi

# Keep hardware measurements for rehearsal. Never persist prompt or response traces.
fifo=$(mktemp -d)/server.log
mkfifo "$fifo"
awk -W interactive -v failure="$runtime/failure" '
    { line = tolower($0) }
    line ~ /offloaded [0-9]+\/[0-9]+ layers|release:.*truncated =|model loaded|entering sleep/ { print; fflush() }
    line ~ /out of memory|cudamalloc.*failed|cuda_error_out_of_memory/ { print "memory" > failure; close(failure) }
    line ~ /no cuda-capable device|invalid device: cuda0|cuda driver version is insufficient/ { print "gpu" > failure; close(failure) }
' < "$fifo" &
rm -f "$runtime/router.sock"
echo starting > "$runtime/failure"
exec /app/llama-server --models-preset /etc/ajar/model.ini --models-max 1 \
    --no-models-autoload --offline --no-ui --api-key-file "$runtime/router.key" \
    --host "0.0.0.0,$runtime/router.sock" --port 8080 > "$fifo" 2>&1
