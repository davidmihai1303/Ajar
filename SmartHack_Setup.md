# Distributed LLM Setup & SmartHack — Reference

_Built on 5 November 2026. This document describes the system as it stands at the end of that session._

---

## 1. What we built

A local LLM server that runs **Qwen3.8 27B** split across two laptops connected by an Ethernet cable, with a small API app (**SmartHack**) in front of it that other devices on the Wi-Fi network can call.

```
Devices on Wi-Fi                MSI (Ubuntu)                                   MacBook Pro
────────────────                ─────────────────────────────────────────      ─────────────────────────
phone / laptop ──Wi-Fi──▶  SmartHack  :8000  (API key required)
                               │
                               │ http://127.0.0.1:8080  (never leaves the MSI)
                               ▼
                           llama-server  127.0.0.1:8080
                               ├── RTX 4070 (CUDA): layers 0–25
                               │
                               └── RPC over cable ──────────────────────────▶  ggml-rpc-server 10.77.0.2:50052
                                   10.77.0.1  ◀───── 1 Gbps direct link ─────▶  Metal (M4 Pro): layers 26–63
                                                                                 + output layer
```

**Roles**

| Machine | Role | What runs there |
|---|---|---|
| **MSI** | Host / server | `llama-server` (the brain: loads the model, splits it, serves the API), SmartHack |
| **MacBook** | RPC worker | `ggml-rpc-server` (a "remote GPU": receives its layers and computes them on Metal) |

The split gives **capacity**: the 27B model fits even though neither machine could hold it comfortably alone. It doesn't make the model faster than a single machine with enough memory would be.

---

## 2. Hardware

| | MSI | MacBook Pro |
|---|---|---|
| CPU | Intel i7-13620H (16 threads) | Apple M4 Pro |
| GPU | NVIDIA RTX 4070 Laptop, 8 GB VRAM (~7.8 GB usable by CUDA) | M4 Pro GPU (unified memory) |
| RAM | 16 GB | 24 GB unified (macOS allows the GPU ~18.6 GB) |
| OS | Ubuntu 26.04 LTS, kernel 7.0.0-42 | macOS |
| Graphics mode | `prime-select on-demand`: the desktop runs on the Intel iGPU, so the 4070 stays free | — |

---

## 3. Network

### 3.1 Direct cable link (fixed: does NOT change when Wi-Fi networks change)

| | MSI | MacBook |
|---|---|---|
| Interface | `enp3s0` (built-in Ethernet port) | **USB 10/100/1000 LAN** adapter, plugged into a Thunderbolt/USB-C port |
| IP | **`10.77.0.1/24`** | **`10.77.0.2`**, mask `255.255.255.0` |
| Gateway / router | none | none (left empty) |
| IPv6 | link-local only | (default) |
| Config | NetworkManager profile `netplan-enp3s0` (`ipv4.method manual`, `ipv6.method link-local`) | System Settings → Network → USB 10/100/1000 LAN → Details → TCP/IP → **Manually** |

- Protocol stack: Gigabit Ethernet → IPv4 → TCP → llama.cpp's own RPC protocol (port 50052).
- Measured: ping **~0.5 ms**, iperf3 **~941 Mbit/s in both directions**, 0 retransmissions.
- No gateway on the cable, so internet traffic stays on Wi-Fi.
- The subnet `10.77.0.0/24` was chosen to be unusual, to avoid clashing with Wi-Fi networks.
- **It would only need changing if:** a Wi-Fi network also uses `10.77.0.x`, a different USB adapter is used on the Mac (then set `10.77.0.2` again), or the cable goes through a router instead of directly between the laptops.

### 3.2 Wi-Fi (CHANGES regularly)

- MSI interface: `wlo1`. Address at the time of writing: `192.168.0.92` (router DHCP).
- **This address will change.** Find the current one with:
  ```bash
  ip -4 addr show wlo1
  ```
- SmartHack clients must use the MSI's current Wi-Fi address.
- (Open item: how to handle changing IPs, see §12.)

### 3.3 Ports

| Port | Service | Machine | Listens on | Reachable from |
|---|---|---|---|---|
| **22** | SSH | MSI | all interfaces | **cable only** (firewall) |
| **8000** | SmartHack | MSI | `0.0.0.0` | Wi-Fi + cable (API key required) |
| **8080** | llama-server | MSI | `127.0.0.1` | **only the MSI itself** |
| **50052** | ggml-rpc-server | Mac | `10.77.0.2` | the MSI over the cable |

### 3.4 Firewall (MSI, ufw)

Active, and enabled at boot.
```
Default: deny (incoming), allow (outgoing), deny (routed)
8000/tcp   ALLOW IN   Anywhere (v4 + v6)
22/tcp     ALLOW IN   10.77.0.0/24
```
- Outgoing is allowed, so the MSI's RPC connection to the Mac works.
- Localhost traffic (SmartHack → llama-server) is never filtered.
- Commands: `sudo ufw status verbose`, `sudo ufw disable` / `sudo ufw enable`.
- The Mac's macOS firewall was inactive at the time of setup.

---

## 4. SSH (Mac → MSI)

| Item | Location |
|---|---|
| Private key | Mac: `~/.ssh/id_ed25519` (never leaves the Mac) |
| Public key | Mac: `~/.ssh/id_ed25519.pub` → installed on the MSI in `~/.ssh/authorized_keys` (via `ssh-copy-id`) |
| Shortcut | Mac: `~/.ssh/config` |

```
Host msi
    HostName 10.77.0.1
    User david
```

- The SSH server on the MSI: `openssh-server`, enabled with `sudo systemctl enable --now ssh`.
- Usage: `ssh msi` (no password). Run one remote command: `ssh msi 'nvidia-smi'`.
- SSH only works **over the cable** (firewall rule). If the cable is unplugged, use the MSI's own keyboard and screen.
- To reach llama-server's web UI from the Mac (it's localhost-only), use a tunnel:
  ```bash
  ssh -L 8080:127.0.0.1:8080 msi     # then open http://localhost:8080 on the Mac
  ```

---

## 5. MSI software stack

| Component | Version / detail |
|---|---|
| NVIDIA driver | `nvidia-driver-595-open` **595.99.02** (supports CUDA ≤ 13.2) |
| Kernel module | `linux-modules-nvidia-595-open-7.0.0-42-generic` |
| CUDA toolkit | **12.4** (Ubuntu package `nvidia-cuda-toolkit`) |
| Host compiler for CUDA | **g++-13** (system default is GCC 15; CUDA 12.4 needs ≤ 13) |
| Build tools | `build-essential`, `cmake`, `git`, `libssl-dev`, `ccache` |
| Persistence mode | **Disabled** on purpose, so the 4070 can power off completely when idle (`runtime_status = suspended`) |
| Ollama | installed, but not used in this setup |

### ⚠️ Kernel updates and the NVIDIA driver

A kernel update once left the system without a matching NVIDIA module (it was held back by phasing), and `nvidia-smi` stopped working. **Don't `apt-mark hold` the driver.** Instead, after every `apt upgrade` and **before rebooting**, check:
```bash
ls /lib/modules/ | sort -V | tail -1                              # newest kernel
apt list --installed 2>/dev/null | grep linux-modules-nvidia       # needs a module for that kernel
```
If it's missing:
```bash
sudo apt install linux-modules-nvidia-595-open-generic-hwe-26.04 nvidia-driver-595-open
```
(The module and driver must be updated together.)

---

## 6. llama.cpp

Both machines **must run the same commit**, because the RPC protocol changes between versions.

| | MSI | Mac |
|---|---|---|
| Source | `~/llama.cpp` | `~/llama.cpp` |
| Commit | **`15e50990b`** (also saved in `~/Desktop/llama_hash.txt` on the MSI) | **`15e50990b`** (detached HEAD) |
| ggml version | 0.29.0 | 0.29.0 |
| Binaries | `~/llama.cpp/build/bin/` (`llama-server`, `llama-cli`, `llama-bench`, `ggml-rpc-server`, …) | `~/llama.cpp/build/bin/ggml-rpc-server` |

> Note: in this version the RPC server binary is named **`ggml-rpc-server`** (not `rpc-server`).

### Build commands

**MSI (CUDA + RPC):**
```bash
cd ~/llama.cpp
cmake -B build \
  -DGGML_CUDA=ON \
  -DGGML_RPC=ON \
  -DCMAKE_CUDA_ARCHITECTURES=89 \
  -DCMAKE_CUDA_HOST_COMPILER=g++-13 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j 8      # -j 8, not 16: nvcc uses a lot of RAM
```

**Mac (Metal + RPC, only the RPC server):**
```bash
cd ~/llama.cpp
cmake -B build -DGGML_METAL=ON -DGGML_RPC=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j --target ggml-rpc-server
```

### Updating llama.cpp later
Update **both** machines to the same new commit, then rebuild both:
```bash
git fetch && git checkout <new-commit>     # on both machines
# then repeat the build commands (ccache makes the MSI rebuild faster)
```

---

## 7. The model

| Item | Value |
|---|---|
| Model | **Qwen3.8 27B** (dense, 64 layers, hybrid attention: only 16 layers use full attention, so the KV cache is small) |
| Quantization | **UD-Q4_K_M** (Unsloth Dynamic 4-bit: mixed q4_K/q5_K/q6_K/iq4/q8_0 per tensor) |
| Source | Hugging Face `unsloth/Qwen3.8-27B-GGUF` |
| File | **`~/models/Qwen3.8-27B-UD-Q4_K_M.gguf`** on the MSI only (16.5 GB) |
| Extra block | `blk.64` = MTP (multi-token prediction) layer; llama.cpp ignores it for now ("unused tensor" warnings are normal) |

The Mac never needs the model file. The MSI sends it its layers.

Download command (for reference):
```bash
mkdir -p ~/models && cd ~/models
curl -L -C - -o Qwen3.8-27B-UD-Q4_K_M.gguf \
  https://huggingface.co/unsloth/Qwen3.8-27B-GGUF/resolve/main/Qwen3.8-27B-UD-Q4_K_M.gguf
```

---

## 8. How the split works

1. At startup, `llama-server` (MSI) reads the model's metadata and splits the 64 layers using `--tensor-split`.
2. `--device CUDA0,RPC0` sets the order: the 4070 gets the **first** layers, and the Mac gets the **last** layers plus the **output layer** (so the 4070's VRAM goes to regular layers only).
3. The token embedding table (~0.7 GB) stays in the MSI's CPU RAM. It's just a lookup, so the GPU isn't needed.
4. The MSI sends the Mac **only its own tensors**. With `-c`, the Mac caches them on disk. Later starts send only hashes, and the Mac loads from its cache.
5. For each generated token: the 4070 runs its layers → ~20 KB of activations go over the cable → the Mac runs its layers + output → ~1 MB of logits come back → the MSI samples the next token.

### Current split: `--tensor-split 41,59`

| | Layers | Memory |
|---|---|---|
| RTX 4070 | ~26 | **7155 MiB used** (~650 MiB headroom; ~265 MiB per layer) |
| Mac (Metal) | ~38 + output | ~10–11 GB |
| MSI RAM | embedding | ~0.7 GB |

Tested stable with a 15K-token prompt. **Don't go to 42/58 or higher**, because there wouldn't be enough headroom for long prompts.

**Changing the split** is a startup flag, not a rebuild: stop llama-server and start it again with a different `--tensor-split`. Each model needs its own ratio.

### Measured performance

| Measurement | Result |
|---|---|
| Generation, short context | **~10.4 tok/s** |
| Generation, 15K context | **~9.4 tok/s** |
| Prompt processing (prefill) | **~152 tok/s** (a 15K-token prompt takes ~100 s) |
| First start (weights over the cable) | ~2 min |
| Later starts (Mac cache) | much faster |

Prefill is the weak point (limited by the Mac's compute). For SmartHack: keep prompts short, put stable content (system prompt, documents) **at the beginning** so `--cache-reuse` can reuse it, and send only the relevant RAG chunks.

---

## 9. Starting everything

**Order matters: Mac first, then MSI.**

### 9.1 Mac: RPC worker (Mac Terminal, keep it open)
```bash
cd ~/llama.cpp
caffeinate -dims ./build/bin/ggml-rpc-server -H 10.77.0.2 -p 50052 -c
```
| Flag | Meaning |
|---|---|
| `caffeinate -dims` | keeps the Mac awake while the server runs |
| `-H 10.77.0.2` | listen only on the cable (the default 127.0.0.1 would block the MSI) |
| `-p 50052` | port |
| `-c` | local tensor cache: **`~/Library/Caches/llama.cpp/rpc`** (~10 GB) |

It should list only `MTL0: Apple M4 Pro`. The red "never expose the RPC server" warning is expected: it has no authentication, which is why it listens only on the cable.

### 9.2 MSI: llama-server (in tmux session `llm`)
```bash
tmux new -s llm            # or: tmux attach -t llm
cd ~/llama.cpp
./build/bin/llama-server -m ~/models/Qwen3.8-27B-UD-Q4_K_M.gguf \
  --rpc 10.77.0.2:50052 --device CUDA0,RPC0 --tensor-split 41,59 -ngl 99 \
  -c 32768 -fa on --cache-type-k q8_0 --cache-type-v q8_0 --jinja \
  --cache-reuse 256 \
  --host 127.0.0.1 --port 8080
```
| Flag | Meaning |
|---|---|
| `--rpc 10.77.0.2:50052` | the Mac's RPC server |
| `--device CUDA0,RPC0` | device order (4070 first, Mac last, so the output layer lands on the Mac) |
| `--tensor-split 41,59` | ~41% of the layers on the 4070, 59% on the Mac |
| `-ngl 99` | all layers on GPUs |
| `-c 32768` | 32K context, shared by 4 automatic slots (unified KV) |
| `-fa on` + `q8_0` KV cache | Flash Attention, KV cache at half the size |
| `--jinja` | apply the model's chat template |
| `--cache-reuse 256` | reuse already-processed prompt prefixes |
| `--host 127.0.0.1` | **localhost only**: nothing outside the MSI can reach it |

Ready when the log shows: `listening on http://127.0.0.1:8080`. Check:
```bash
curl http://127.0.0.1:8080/health          # {"status":"ok"}
nvidia-smi --query-gpu=memory.used,memory.total --format=csv
```

### 9.3 MSI: SmartHack (in its own tmux session)
```bash
tmux new -s smarthack
cd ~/Desktop/SmartHack
source .venv/bin/activate
export APP_API_KEY="$(cat .api_key)"
uvicorn app:app --host 0.0.0.0 --port 8000
```
Leave tmux with `Ctrl+B`, then `D`. Come back with `tmux attach -t smarthack`.

### Restart rules
| Event | What to do |
|---|---|
| llama-server restarted | nothing else; it reconnects to the Mac on its own |
| **ggml-rpc-server restarted (Mac)** | **restart llama-server too** (it loses its layers on the Mac) |
| MSI rebooted | start llama-server, then SmartHack (Mac first if it was also restarted) |

---

## 10. SmartHack

| Item | Value |
|---|---|
| Location (MSI) | **`~/Desktop/SmartHack/`** |
| Code | `app.py` (FastAPI) |
| Python env | `~/Desktop/SmartHack/.venv` (packages: `fastapi`, `uvicorn`, `openai`) |
| Listens on | `0.0.0.0:8000` |
| Talks to | `http://127.0.0.1:8080/v1` (llama-server, OpenAI-compatible API) |

### Endpoints
| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | `{"app":"SmartHack","status":"ok"}` |
| `POST /chat` | **`X-API-Key` header** | body `{"message": "..."}` → streams the answer as plain text |
| `GET /docs` | none | FastAPI's interactive documentation |

### The API key
| Item | Detail |
|---|---|
| File | **`~/Desktop/SmartHack/.api_key`** on the MSI, permissions `-rw-------` (only user `david`) |
| Format | 43 characters, generated with `secrets.token_urlsafe(32)` |
| How the app gets it | environment variable `APP_API_KEY`, read **once at startup** (`export APP_API_KEY="$(cat .api_key)"`) |
| Copy | kept by the owner outside the machine (currently in WhatsApp; a password manager is recommended) |
| Read it from the Mac | `ssh msi 'cat ~/Desktop/SmartHack/.api_key'` (runs on the MSI; nothing is copied to the Mac) |

**Rotate the key** (if it's exposed):
```bash
cd ~/Desktop/SmartHack
umask 077
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > .api_key
# then restart SmartHack so it loads the new key
```
Never paste the full key into chats or commands that get saved in shell history. If `.api_key` ever goes into git, add it to `.gitignore`.

### Calling SmartHack
```bash
curl -N http://<MSI-WIFI-IP>:8000/chat \
  -H "X-API-Key: PASTE_KEY_HERE" \
  -H "Content-Type: application/json" \
  -d '{"message": "Say hello in Romanian."}'
```
(No space after a trailing `\`. Without a valid key you get `401 Unauthorized`.)

---

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `nvidia-smi`: "couldn't communicate with the NVIDIA driver" | new kernel without an NVIDIA module (see §5) |
| `address already in use` on port 8000 | an old SmartHack is still running: `pkill -f "uvicorn app:app"` |
| `401 Invalid or missing API key` | the key in the request ≠ the key SmartHack loaded at startup; restart SmartHack after `export APP_API_KEY="$(cat .api_key)"` |
| `KeyError: 'APP_API_KEY'` | the variable isn't set in this shell; export it before `uvicorn` |
| Commands typed in a terminal "do nothing" | that terminal is running a foreground program (uvicorn/llama-server); use `Ctrl+C`, another terminal, or tmux |
| llama-server can't reach the Mac | is `ggml-rpc-server` running on the Mac? Test: `ping 10.77.0.2`; `llama-server --rpc 10.77.0.2:50052 --list-devices` |
| CUDA out of memory | lower the 4070's share (`--tensor-split 39,61`) |
| SSH stops working | firewall allows SSH only from `10.77.0.0/24`, so check the cable; or a VPN on the Mac is capturing local traffic |
| Mac RPC cache too large / switching models | `rm -rf ~/Library/Caches/llama.cpp/rpc` |

**Useful checks**
```bash
# MSI
ip -4 addr show enp3s0 wlo1
nvidia-smi
cat /sys/bus/pci/devices/0000:01:00.0/power/runtime_status   # suspended = 4070 powered off
sudo ufw status verbose
tmux ls

# Mac
ping -c 4 10.77.0.1
route get 10.77.0.1        # should go through the USB LAN adapter, not Wi-Fi
du -sh ~/Library/Caches/llama.cpp/rpc
```

---

## 12. Open items

- [ ] **Changing Wi-Fi IPs**: the MSI's Wi-Fi address changes regularly; a solution is still to be decided. (The cable IPs are unaffected.)
- [ ] **Services**: systemd units on the MSI (llama-server, SmartHack, reading the key from `.api_key`) and launchd on the Mac (`ggml-rpc-server`), so everything starts on boot and restarts on its own instead of relying on tmux.
- [ ] **SSH hardening**: verify/set `PasswordAuthentication no` and `PermitRootLogin no` on the MSI.
- [ ] **Server hardening suggested by Claude Code** (status to verify): lid-close behavior (`HandleLidSwitch=ignore`), GRUB default to Ubuntu, Windows Fast Startup off.
- [ ] **Optional**: disable the unused Ollama service (`sudo systemctl disable --now ollama`) so nothing else takes the 4070's VRAM.
- [ ] **SmartHack improvements**: system prompt, conversation history, reasoning/"thinking" control, a web interface, HTTPS (e.g. Caddy) if needed.
- [ ] **Possible speed-ups**: MTP / speculative decoding (if supported), or a smaller/MoE model for simple tasks.
