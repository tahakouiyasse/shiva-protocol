<div align="center">

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗████████╗██╗   ██╗███╗   ███╗         ║
║   ██╔═══██╗██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██║   ██║████╗ ████║         ║
║   ██║   ██║██║   ██║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║         ║
║   ██║▄▄ ██║██║   ██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║         ║
║   ╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║         ║
║    ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝         ║
║                                                                               ║
║                  A  R  C  H                                                   ║
║                                                                               ║
║         Zero-allocation. eBPF-native. Adversary-hostile.                     ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

**A deterministic intrusion detection and active defense protocol for hardened Linux systems.**

[![Rust](https://img.shields.io/badge/Rust-1.77%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Kernel](https://img.shields.io/badge/Kernel-5.8%2B%20%28BTF%29-blue?style=flat-square&logo=linux)](https://www.kernel.org/)
[![Architecture](https://img.shields.io/badge/Architecture-eBPF%2FXDP-blueviolet?style=flat-square)](https://ebpf.io/)
[![Memory](https://img.shields.io/badge/Hot--Path%20Alloc-Zero-green?style=flat-square)](.)
[![Latency](https://img.shields.io/badge/P99%20Latency-%3C100ns-red?style=flat-square)](.)
[![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)](LICENSE)

</div>

---

## What Is This

Quantum Arch is a production-grade **network intrusion detection and active defense protocol** written in Rust, operating at the Linux kernel boundary via eBPF/XDP.

It does not detect threats with signatures. It detects them **statistically** — using mathematical models borrowed from high-frequency trading and applied to network traffic flow analysis:

| Model | Origin | Application |
|---|---|---|
| **VPIN** | Order flow toxicity detection | Directional imbalance → scanning, exfiltration, DDoS |
| **SSA** | Financial time-series decomposition | Structural anomaly extraction from inter-packet latency |
| **EKF** | Non-linear state estimation | Behavioural trajectory modelling + deviation detection |
| **Hurst Exponent** | Fractal time-series analysis | Distinguishes persistent attacks from random noise |
| **Rényi Entropy** | Information theory | Encrypted tunnel detection without payload inspection |

Adversaries are not simply blocked. They are **exhausted, deceived, and trapped.**

---

## Architecture

Three Rust crates. One clean boundary between kernel and userspace.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   NIC / Wire  ──►  XDP Hook  ──►  Ring Buffer  ──►  7-Stage Pipeline       │
│                                                                             │
│   VPIN ─► MTU-Track ─► SSA ─► Entropy ─► EKF ─► Hurst ─► Bellman Score   │
│                                                                             │
│   Output:  DROP  │  TAR-PIT  │  HONEYPOT  │  LOG                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

| Crate | Layer | Role |
|---|---|---|
| `sg-common` | Shared ABI | Defines `SignalFrame` — a 64-byte, cache-line-aligned packet contract |
| `sg-ebpf` | Kernel (XDP) | Zero-copy packet capture via `BPF_MAP_TYPE_RINGBUF`; pre-stack interception |
| `sg-capture` | Userspace | 32-thread lock-free analysis engine and active defense dispatcher |

### The Hot Path

```
NIC ──► XDP (sg-ebpf) ──zero-copy──► Ring Buffer
                                           │
                                      T1: Capture        (ingestion, no decisions)
                                           │
                                      T2: Analysis       (7-stage pipeline)
                                           │
                                      T3: Reaction       (tar-pit / DROP / DNAT)
                                           │
                              ┌────────────┼────────────┐
                           SIEM         nftables      Honeypot
                        (JSON/TLS)
```

> **Invariant:** After `init()`, zero heap allocations occur on any hot path. A custom allocator wrapper `panic!`s on any violation — making this guarantee compile-time auditable.

---

## Detection Engine — 7 Stages

Every suspicious flow traverses a sequentially gated pipeline. **All seven gates must trigger.** This architecture minimises false positives structurally, not through threshold tuning.

### Stage 1 — VPIN (Volume-Synchronized Probability of Informed Trading)

Packets aggregate into 10,000-unit buckets. Directional imbalance across a 50-bucket sliding window signals scanning, exfiltration, or DDoS.

```
         1    n
VPIN = ─────  Σ  |V_i_in − V_i_out|
        n·V  i=1
```

**Gate:** `VPIN ≥ 0.72` → pipeline continues.

---

### Stage 2 — MTU-Track

Mean packet size tracked over a 100k-slot circular window via Welford's online algorithm (O(1), zero allocation).

- **≥ 40% drop** in mean size → port scan pattern → triggers Deceptive Fingerprinting
- **Sustained increase** over ≥ 10 epochs → tunneling or exfiltration

---

### Stage 3 — SSA (Singular Spectrum Analysis)

Decomposes inter-packet latency into structural components via SVD. The dominant reconstructed component RC₁ filters signal from noise.

```
X = U Σ Vᵀ,    RC₁ = σ₁ u₁ v₁ᵀ
```

A **±15% eigenvalue shift** over 10 buckets declares a structural anomaly. Catches DDoS ramp-up and tunneling that volume-based systems miss entirely.

> SSA and Hurst are amortised over 5-second epochs in a background thread. Their contribution to P99 hot-path latency is **zero by design.**

---

### Stage 4 — Dual Entropy

Detects encrypted exfiltration and covert tunnels **without inspecting payload content.** Computed over a stack-resident 32-bin histogram. Zero heap allocation.

```
Shannon:  H_S = −Σ p_b · log₂(p_b)           → H_S > 0.95 on non-standard port = ENCRYPTED_EXFIL
Rényi:    H_2 = −log₂(Σ p_b²)                → concentration spike              = ENCRYPTED_TUNNEL
```

---

### Stage 5 — Extended Kalman Filter

Models network behaviour as a dynamical system `[position, velocity, acceleration]`. Predicts expected state; flags deviations exceeding **2.7σ**.

```
Measurement noise is adaptive — VPIN-weighted:
  R_k = R₀ · (1 + α · VPIN_k),   α = 2.0
```

**Anti-poisoning:** Every 24 hours, the EKF resets from a cryptographically signed `baseline_gold.json` (HMAC-SHA256). This prevents adversaries from slowly training the model to accept malicious behaviour as normal.

---

### Stage 6 — Hurst Exponent + Z-Score (Double Gate)

```
H ≈ log(R/S) / log(n)
```

| H Value | Interpretation |
|---|---|
| H ≈ 0.5 | Random noise — legitimate traffic |
| H > 0.65 | Persistent, structured behaviour — confirmed attack campaign |

Both `H > 0.65` **and** `Z > 2.3` on the Kalman innovation must be true simultaneously. This double gate is the primary false-positive suppressor.

---

### Stage 7 — Bellman Composite Score

```
S_final = 0.40 · H_entropy + 0.30 · VPIN + 0.30 · ε_EKF_norm
```

Self-calibrating against a 30-day rolling distribution. Only the **top 5%** trigger automated action. No manual threshold tuning required.

| Score Percentile | Classification | Response |
|---|---|---|
| < 60% | Benign | Log only |
| 60–90% | Suspicious | Adaptive Tar-Pit |
| > 90% | Confirmed Threat | DROP or Honeypot |
| eBPF kernel correlation hit | Override | Immediate max score |

---

## Active Defense

### Adaptive Tar-Pit (60–90%)

The attacker is not blocked — they are **slowed without knowing it.**

- **TCP Window Zero** → forces exponential back-off. The attacker burns their own resources.
- **`tc` jitter injection** → 200–400ms variable delay, 25% dispersion. Connection feels broken. Attack tooling stalls.

### Shifting Ghost Honeypot (> 90%)

Connection is silently `DNAT`'d mid-session to an isolated decoy container. The attacker believes they are inside the real target.

```nftables
nft add rule ip nat prerouting \
    ip saddr <attacker_ip> tcp dport 22 \
    dnat to 10.1.1.100:2222
```

Inside: realistic SSH shell, HTTP/HTTPS responses, service banners. Every keystroke logged for IOC extraction and attacker profiling.

### Deceptive Fingerprinting

Triggered on scan detection. The `sg-ebpf` XDP layer modifies outgoing TCP headers **for that flow only:**

- **TTL altered** (e.g., 128 → 64) — implies a different OS family
- **MSS changed** (e.g., 1460 → 1200) — implies a non-standard path MTU
- **Synthetic unknown TCP options injected** — produces fingerprints matching no real OS in Nmap, p0f, or Zmap databases

Adversary reconnaissance returns **contradictory, unusable intelligence.**

---

## Performance

All figures at **P99** on a single modern x86-64 core.

| Stage | Target Latency |
|---|---|
| XDP header extraction | < 20 ns |
| Ring buffer submission | < 5 ns |
| Userspace frame poll (zero-copy) | < 10 ns |
| VPIN bucket update | < 15 ns |
| EKF predict + update | < 20 ns |
| Entropy (stack histogram) | < 15 ns |
| Action dispatch | < 15 ns |
| **Total hot-path P99** | **< 100 ns** |

- **Throughput:** 50,000+ PPS per interface before flood threshold
- **Memory:** 256 MB fixed arena — no growth under any traffic condition
- **CPU:** < 5% on a single modern core at 10,000 PPS; scales across 32 pinned worker threads
- **SSA + Hurst:** amortised over 5-second epochs, never blocking the capture pipeline

---

## Deployment

```bash
# 1. Compile with BTF support (requires Linux kernel 5.8+)
cargo build --release --package sg-ebpf

# 2. Load XDP program on target interface
quantum-arch attach --iface eth0

# 3. Start in read-only calibration mode
quantum-arch start --mode readonly

# 4. After 7 days, generate signed baseline
quantum-arch baseline generate
# → produces baseline_gold.json (HMAC-SHA256 signed)

# 5. Human operator validates baseline with network specialist
quantum-arch baseline validate

# 6. Enable production mode
quantum-arch mode auto

# 7. Configure SIEM endpoint in config.toml
# 8. Set RBAC principals in rbac.toml  (Admin / SOC Operator / Auditor)
```

> **Production mode requires explicit human validation of the signed baseline. No automated actions fire before this gate.**

### Operational Modes

| Mode | Behaviour |
|---|---|
| **Automatic** | All ≥ 90% flows trigger automated response. Default. |
| **Semi-Manual** | Alerts generated; humans approve all actions. Activated when block rate exceeds 10/hour or attack is slow/low-volume. |
| **KillSwitch** | Full automation suspended. Observer mode. Maximum forensic logging. |

---

## Operational Lifecycle

```
Days 1–7          Day 7             Production         Ongoing
─────────────     ─────────────     ─────────────     ─────────────
Read-Only Mode  → Sign Baseline   → Auto Actions    → Feedback Loop
Collect traffic   Validate &        enable            Threshold
profiles          FP/TP labels                        auto-adjustment
```

---

## SIEM Integration

Emits structured JSON over TLS:

```json
{
  "timestamp":    "2026-05-01T14:23:11.482Z",
  "src_ip":       "203.0.113.0",
  "dst_port":     443,
  "score":        0.94,
  "anomaly_type": "ENCRYPTED_EXFIL",
  "action_taken": "HONEYPOT_REDIRECT",
  "hurst_h":      0.71,
  "vpin":         0.83,
  "ekf_z":        3.1
}
```

Compatible with: **Elastic SIEM, Splunk, Graylog, IBM QRadar, Prometheus, Grafana,** and any SIEM accepting JSON-over-TLS.

**Embedded HTTP API:**
- Real-time score distribution histograms
- Active high-risk flow table with live score updates
- `POST /label {alert_id, verdict: "fp" | "tp"}` — operator feedback feeds the auto-tuning loop

---

## Governance

| Concern | Implementation |
|---|---|
| **RBAC** | Security Administrator / SOC Operator / Auditor (read-only) |
| **Audit trail** | Every config change logged with `(who, when, what, file-hash)` |
| **Data retention** | Detection logs 90 days; raw flow metadata 7 days |
| **GDPR** | IP pseudonymisation (last-octet masking) available for EU deployments. All log egress over TLS only. |
| **Whitelist integrity** | Signed `whitelist.json` — any unsigned modification suspends automatic mode until re-validated |

---

## Design Rationale

The detection models originate from **high-frequency financial trading** — a domain where detecting informed actors inside noisy, adversarial data streams is a billion-dollar problem.

- **VPIN** was developed to detect market manipulation by identifying directional flow toxicity.
- **SSA** was developed to extract structural signals from financial time series contaminated by noise and cyclical artifacts.
- **EKF** models non-linear dynamical system state under uncertainty.
- **Hurst Exponent** distinguishes persistent, structured behaviour from memoryless random processes.

Applied to network traffic, these models detect adversarial actors with a statistical depth that pure packet-counting cannot achieve. **The adaptation is the contribution.**

---

## Documentation

| Document | Description |
|---|---|
| 📄 [Technical White Paper](https://github.com/tahakouiyasse/shiva-protocol/blob/main/docs/White_Paper.pdf) | Full mathematical specification: all 7 stages with formal proofs, architecture diagrams, performance tables, and bibliography |
| 📘 [White Paper — Critical Infrastructures](https://github.com/tahakouiyasse/shiva-protocol/blob/main/docs/White_Paper_Critical_Infrastructures.pdf) | Application of the statistical models to critical infrastructure protection, adversarial signal environments, and hardened network defense |

---

## References

1. Easley, D., Lopez de Prado, M., & O'Hara, M. — *The Exchange of Flow Toxicity*, Journal of Portfolio Management, 2011
2. Golyandina, N., Nekrutkin, V., Zhigljavsky, A. — *Analysis of Time Series Structure: SSA and Related Techniques*, CRC Press, 2001
3. Kalman, R. E. — *A New Approach to Linear Filtering and Prediction Problems*, 1960
4. Hurst, H. E. — *Long-Term Storage Capacity of Reservoirs*, 1951
5. Rényi, A. — *On Measures of Entropy and Information*, 1961
6. Høiland-Jørgensen et al. — *The eXpress Data Path*, ACM CoNEXT, 2018
7. Aya-rs — eBPF library for Rust — https://github.com/aya-rs/aya
8. Gregg, B. — *BPF Performance Tools*, Addison-Wesley, 2019

---

## Author

**Taha Kouiyasse** — Independent Systems Architect & Protocol Designer  
*Quantum Arch Research Initiative*

Specialization: High-performance protocol architecture, statistical adversarial detection, zero-allocation systems design.

> Available for institutional engagement, technical review sessions, and proof-of-concept collaborations.

---

<div align="center">

**Quantum Arch v2.2** — Technical White Paper Rev. 2.2 — May 2026

*Zero-allocation. eBPF-native. Adversary-hostile.*

</div>
