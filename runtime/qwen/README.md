# Ajar with local Qwen

The offline bundle targets Linux x86-64 with Docker Engine and Compose 2.24 or newer.
GPU chat requires a CUDA 12.8-compatible NVIDIA driver and NVIDIA Container Toolkit configured
for Docker. The installer also uses Python 3, Bash, flock and GNU coreutils, available on the
target Ubuntu laptop. Live scanning uses the separate host setup documented in the project README.

## Install the release

Download all the release files into one folder. In that folder, extract
`ajar-setup.tar.gz` and run `bash ajar/install.sh` as your normal Docker user.
Installation verifies the parts, loads both images and restores the model locally.
It requires roughly 25 GiB free in addition to the download, including Docker storage.
Open **http://127.0.0.1:8001**. For subsequent starts use `bash runtime/qwen/start.sh`
in the extracted `ajar` directory. The installation, startup and chat work offline.

## Use the chat

Open an imported or live scan, go to **Ask**, type a question and accept the existing AI
consent prompt. Questions about the score and addresses outside the scan are handled
immediately. When inference is needed the chat shows the loading message and answers the
pending question. A failed load offers a reason and **Try again** on the same message.
The packaged server releases model memory after 10 idle minutes. **Turn off the local
assistant** unloads it immediately. The app, built-in guidance and CSV export work on a
machine without GPU support.

To grade a folder offline, put the XML files in `input/test_set/` and run the following
command from the extracted directory. Both CSVs appear in `input/results/`.

```bash
docker compose -f docker-compose.yml -f compose.qwen.yml run --rm --no-deps --pull never \
  app netcheck analyze /data/input/test_set --out /data/input/results
```

The CUDA router publishes port 8080 only on host loopback. Ajar uses the HTTP endpoint
`http://127.0.0.1:8080/v1` over a private Unix socket shared with that container.
An unrelated listener on the port cannot receive scan data. An explicit `LLM_BASE_URL`
in your app environment selects your separately managed local endpoint. Ajar does not manage
its lifecycle. The packaged runtime uses one 4,096-token inference slot and Qwen3.5-9B Q4_K_M.

## Build and verify

From a source checkout on an online build machine, run
`bash runtime/qwen/pack.sh /path/to/empty/output`. Optionally pass a local GGUF as a
second argument to reuse a download. The script builds the Linux app image, pulls the pinned
CUDA image, verifies the exact weights, and splits the assets below 2 GiB for distribution.
The release includes the model and runtime licenses.

On the **RTX 4070 laptop**, disconnect the internet after installation, close other GPU
workloads, and run `bash runtime/qwen/verify-gpu.sh`. It sends synthetic questions in
both languages and checks accepted evidence, layer offload and prompt fit. It prints cold
latency and peak total device memory. Leave Ask open for ten minutes, check the drop in
`nvidia-smi`, send another question, then turn AI off. Import the validation scans and
compare the generated CSVs with the supplied answers in both modes.
