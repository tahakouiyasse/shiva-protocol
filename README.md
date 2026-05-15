# ⚡ Quantum Arch — v2.2

> **Zero-allocation. eBPF-native. Adversary-hostile.**
> A deterministic intrusion detection and adaptive defense protocol for hardened Linux systems.

📄 **[Read the Full Technical White Paper](https://github.com/tahakouiyasse/shiva-protocol/blob/main/docs/White_Paper.pdf)**

---
┌─────────────────────────────────────────────────────────────────┐
│  NIC / Wire  →  XDP Hook  →  Ring Buffer  →  7-Stage Pipeline  │
│                                                                 │
│  VPIN → MTU → SSA → Entropy → EKF → Hurst → Bellman            │
│                                                                 │
│  Output: DROP | TAR-PIT | HONEYPOT | LOG                        │
└─────────────────────────────────────────────────────────────────┘

---

## What Is This

Quantum Arch is a **production-grade network intrusion detection and active defense protocol** written in Rust, operating at the Linux kernel boundary via eBPF/XDP.

It does not detect threats with signatures. It detects them **statistically** — using mathematical models borrowed from high-frequency trading (VPIN, EKF, SSA) and applied to network traffic flow analysis.

Adversaries are not simply blocked. They are **exhausted, deceived, and trapped**.

---

## Architecture

Three Rust crates. One clean boundary between kernel and userspace.

| Crate | Layer | Role |
|---|---|---|
| `sg-common` | Shared ABI | Defines the `SignalFrame` — a 64-byte, cache-line-aligned packet contract |
| `sg-ebpf` | Kernel (XDP) | Zero-copy packet capture via `BPF_MAP_TYPE_RINGBUF`, pre-stack interception |
| `sg-capture` | Userspace | 32-thread lock-free analysis engine and active defense dispatcher |

### The Hot Path
NIC → XDP (sg-ebpf) ──zero-copy──▶ Ring Buffer
│
T1: Capture (ingestion, no decisions)
│
T2: Analysis (7-stage pipeline)
│
T3: Reaction (tar-pit / DROP / DNAT)
│
SIEM (JSON/TLS) + nftables + Honeypot

**Invariant:** After `init()`, zero heap allocations on any hot path. Custom allocator wrapper panics on violation.

---

## Detection Engine — 7 Stages

Every suspicious flow traverses a sequentially gated pipeline. **All seven gates must pass.** This architecture minimizes false positives.

### Stage 1 — VPIN (Volume-Synchronized Probability of Informed Trading)
Packets aggregate into 10,000-unit buckets. Directional imbalance across a 50-bucket sliding window signals scanning, exfiltration, or DDoS.

$$\text{VPIN} = \frac{1}{nV_0} \sum_{i=1}^{n} \left| V_i^{in} - V_i^{out} \right|$$

**Gate:** `VPIN ≥ 0.72` → pipeline continues.

### Stage 2 — MTU-Track
Mean packet size tracked over the 100k-slot circular window. A ≥40% drop flags scanning. A sustained increase flags tunneling or exfiltration. Triggers **Deceptive Fingerprinting**.

### Stage 3 — SSA (Singular Spectrum Analysis)
Decomposes inter-packet latency into structural components via SVD. The dominant reconstructed component `RC₁` filters signal from noise. A ±15% eigenvalue shift over 10 buckets declares a structural anomaly.

$$X = U\Sigma V^\top, \quad RC_1 = \sigma_1 u_1 v_1^\top$$

Catches DDoS ramp-up and tunneling that volume-based systems miss entirely.

### Stage 4 — Dual Entropy
Detects encrypted exfiltration and covert tunnels without inspecting payload content.

- **Shannon entropy** (`HS > 0.95` on non-standard port) → `ENCRYPTED_EXFIL`
- **Rényi entropy α=2** (concentration spike on non-standard port) → `ENCRYPTED_TUNNEL`

Computed over a **stack-resident** 32-bin histogram. Zero heap allocation.

### Stage 5 — Extended Kalman Filter
Models network behavior as a dynamical system `[position, velocity, acceleration]`. Predicts expected state; flags deviations exceeding `2.7σ`. Measurement noise is adaptive — VPIN-weighted.

**Anti-poisoning:** Every 24h, EKF resets from a cryptographically signed `baseline_gold.json`. This prevents adversaries from slowly training the model to accept malicious behavior as normal.

### Stage 6 — Hurst Exponent + Z-Score (Double Gate)

$$H \approx \frac{\log(R/S)}{\log(n)}$$

- `H ≈ 0.5` → random noise, ignore.
- `H > 0.65` → structured, persistent behavior. Confirmed attack campaign.

Both `H > 0.65` **and** `Z > 2.3` on the Kalman innovation must be true simultaneously. This double gate is the primary false-positive suppressor.

### Stage 7 — Bellman Composite Score

$$S_{final} = 0.40 \cdot H_{entropy} + 0.30 \cdot \text{VPIN} + 0.30 \cdot \epsilon^{norm}_{EKF}$$

Self-calibrating against a 30-day rolling distribution. **Only the top 5% trigger automated action.** No manual threshold tuning required.

| Score Percentile | Classification | Response |
|---|---|---|
| < 60% | Benign | Log only |
| 60–90% | Suspicious | Adaptive Tar-Pit |
| > 90% | Confirmed Threat | DROP or Honeypot |
| eBPF kernel correlation hit | Override | Immediate max score |

---

## Active Defense

### Adaptive Tar-Pit (60–90%)
The attacker is not blocked — they are slowed without knowing it.
- **TCP Window Zero** → forces exponential back-off. Attacker burns their own resources.
- **tc jitter injection** → 200–400ms variable delay, 25% dispersion. Connection feels broken. Attack tooling stalls.

### Shifting Ghost Honeypot (> 90%)
Connection is silently DNAT'd mid-session to an isolated decoy container. The attacker believes they are inside the real target.

```bash
nft add rule ip nat prerouting \
  ip saddr <attacker_ip> tcp dport 22 \
  dnat to 10.1.1.100:2222
```

Inside: realistic SSH shell, HTTP/HTTPS responses, service banners. Every keystroke logged for IOC extraction and attacker profiling.

### Deceptive Fingerprinting
Triggered on scan detection. eBPF modifies outgoing TCP headers **for that flow only**:
- TTL altered (e.g., 128 → 64) — implies different OS family.
- MSS changed (e.g., 1460 → 1200) — implies non-standard path.
- Synthetic unknown TCP options injected — produces fingerprints matching **no real OS** in Nmap, p0f, or Zmap databases.

Adversary reconnaissance returns contradictory, useless data.

---

## Performance

All figures at P99.

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
- **SSA + Hurst:** amortized over 5-second epochs, never blocking capture pipeline

---

## Operational Lifecycle
Days 1–7          Day 7             Production        Ongoing
─────────────     ─────────────     ─────────────     ─────────────
Read-Only Mode  → Sign Baseline  → Auto Actions   → Feedback Loop
Collect traffic   Validate &        FP/TP labels
profiles          enable            Threshold auto-adjustment

Production mode requires **explicit human validation** of the signed baseline. No automated actions fire before this gate.

### Operational Modes

| Mode | Behavior |
|---|---|
| `Automatic` | All ≥ 90% flows trigger automated response. Default. |
| `Semi-Manual` | Alerts generated; humans decide all actions. Triggered by > 10 blocks/hour or slow/low-volume attack patterns. |
| `KillSwitch` | Full automation suspended. Observer mode. Maximum forensic logging. |

---

## SIEM Integration

Emits structured JSON over TLS:

```json
{
  "timestamp": "...",
  "src_ip": "...",
  "dst_port": 443,
  "score": 0.94,
  "anomaly_type": "ENCRYPTED_EXFIL",
  "action_taken": "HONEYPOT_REDIRECT"
}
```

Compatible with: **Elastic SIEM, Splunk, Graylog, IBM QRadar, Prometheus, Grafana**, and any SIEM accepting JSON-over-TLS.

Embedded HTTP API:
- Real-time score distribution histograms
- Active high-risk flow table with live score updates
- `POST /label {alert_id, verdict: "fp" | "tp"}` — operator feedback feeds the auto-tuning loop

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
# 8. Set RBAC principals in rbac.toml (Admin / SOC Operator / Auditor)
```

Config: `config.toml` (arena size, thread count, SIEM TLS endpoint)  
RBAC: `rbac.toml` (three roles: Security Administrator, SOC Operator, Auditor)

---

## Governance

- **RBAC:** Security Administrator / SOC Operator / Auditor (read-only)
- **Audit trail:** Every config change logged with `(who, when, what, file-hash)`
- **Data retention:** Detection logs 90 days; raw flow metadata 7 days
- **GDPR:** IP pseudonymization (last octet masking) available for EU deployments. All log egress over TLS only.
- **Whitelist:** Signed `whitelist.json` — any modification suspends automatic mode until re-validated.

---

## Design Rationale

The detection models come from high-frequency financial trading — a domain where detecting informed actors inside noisy, adversarial data streams is a billion-dollar problem. VPIN was developed to detect market manipulation. SSA to extract structural signals from financial time series. EKF to model non-linear system dynamics.

Applied to network traffic, these models detect adversarial actors with a statistical depth that pure packet-counting cannot achieve. The adaptation is the contribution.

---

## References

- Easley, Lopez de Prado, O'Hara — *The Exchange of Flow Toxicity*, Journal of Portfolio Management, 2011
- Golyandina, Nekrutkin, Zhigljavsky — *Analysis of Time Series Structure: SSA and Related Techniques*, CRC Press, 2001
- Kalman — *A New Approach to Linear Filtering and Prediction Problems*, 1960
- Hurst — *Long-Term Storage Capacity of Reservoirs*, 1951
- Høiland-Jørgensen et al. — *The eXpress Data Path*, ACM CoNEXT, 2018
- Aya-rs — *eBPF library for Rust*, https://github.com/aya-rs/aya
- Gregg — *BPF Performance Tools*, Addison-Wesley, 2019
- Rényi — *On Measures of Entropy and Information*, 1961

---

## Author

**Taha Kouiyasse** — Independent Systems Architect & Protocol Designer  
*Quantum Arch Research Initiative*

Specialization: High-performance protocol architecture, AI-augmented system design, adversarial network defense.

*Available for institutional engagement, technical review sessions, and proof-of-concept collaborations.*

---

<sub>Quantum Arch v2.2 — Technical White Paper Rev. 2.2 — May 2026</sub>
