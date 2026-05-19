<div align="center">

  <h1>qcryptool</h1>
  
  <p>
    <strong>A Pure Rust Tool for Quantum Cryptography Simulation</strong>
  </p>

  <img src="./assets/qcryptool_logo.png" alt="qcrypto logo" width="150">
    
  [![Pure Rust](https://img.shields.io/badge/Pure-Rust-orange)](https://www.rust-lang.org)
  [![Crates.io](https://img.shields.io/crates/v/qcryptool.svg)](https://crates.io/crates/qcryptool)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
  [![Rust CI](https://github.com/jorgegardiaz/qcryptool/actions/workflows/test.yml/badge.svg)](https://github.com/jorgegardiaz/qcryptool/actions/workflows/test.yml)
  ![Coverage](https://raw.githubusercontent.com/jorgegardiaz/qcryptool/master/.github/badges/coverage.svg)

  <br/> 

</div>

CLI simulator for quantum cryptography protocols, powered by [qcrypto](https://github.com/jorgegardiaz/qcrypto).

## Installation

### From crates.io (recommended)

Requires [Rust](https://rustup.rs) 1.85 or later.

```bash
cargo install qcryptool
```

The binary is added to `~/.cargo/bin/` and available system-wide as `qcryptool`.

### From source

```bash
git clone https://github.com/jorgegardiaz/qcryptool.git
cd qcryptool
cargo build --release
```

The compiled binary is placed at `target/release/qcryptool`. You can run it directly or copy it to a directory on your `$PATH`:

```bash
cp target/release/qcryptool ~/.local/bin/
```

---

## Protocols

| Subcommand   | Protocol                                                        |
|--------------|-----------------------------------------------------------------|
| `bb84`       | BB84 QKD — Bennett & Brassard (1984)                           |
| `b92`        | B92 QKD — Bennett (1992)                                       |
| `bbm92`      | BBM92 QKD — Bennett, Brassard & Mermin (1992), entanglement-based BB84 |
| `e91`        | E91 QKD — Ekert (1991), entanglement + Bell inequality test    |
| `six-state`  | Six-State QKD — Pasquinucci & Gisin (1999)                    |
| `sarg04`     | SARG04 QKD — Scarani, Acín, Ribordy & Gisin (2004)            |
| `qia-qzkp`   | QIA-QZKP — Quantum Identity Authentication via Zero-Knowledge Proof |
| `gc01`       | GC01 QDS — Gottesman & Chuang (2001) Quantum Digital Signature |

---

## Basic usage

```bash
# Single shot, identity channel (no noise)
qcryptool bb84 -n 1000

# 100 shots, depolarizing noise p=0.03, save to CSV
qcryptool bb84 -n 1024 -s 100 --channel1 depolarizing --p1 0.03 -o results.csv

# Entanglement-based with asymmetric noise on Alice and Bob
qcryptool bbm92 -n 1000 --channel1 depolarizing --p1 0.01 --channel2 depolarizing --p2 0.04

# Reproducible run (each shot seeded with seed + i)
qcryptool bb84 -n 1000 -s 50 --seed 42 -o out.csv

# Include raw key hex in output
qcryptool bb84 -n 512 --detail
```

### Common flags (all protocols)

| Flag | Description |
|------|-------------|
| `-n` / `--num-qubits` | Qubits / pairs / rounds per shot |
| `-s` / `--shots` | Number of independent runs |
| `-o` / `--output` | Output file (`.json`, `.csv`, or `.txt`) |
| `--channel1` | Channel model for Alice (see table below) |
| `--p1` | Primary noise probability p₁ ∈ [0, 1] |
| `--q1` | Second noise parameter q₁ ∈ [0, 1] (`amplitude-phase-damping` only) |
| `--channel-config` | JSON file defining a channel mix (overrides `--channel1` / `--p1`) |
| `--eve-ratio` | Probability of Eve intercepting each qubit ∈ [0, 1] |
| `--check-ratio` | Fraction of sifted bits sacrificed for QBER estimation ∈ [0, 1] |
| `--seed` | RNG seed for reproducible simulations (shot `i` uses `seed + i`) |
| `--detail` | Include raw keys / commitment vectors in the output |

Entanglement-based protocols (BBM92, E91) and GC01 additionally accept `--channel2` / `--p2` / `--q2` (Bob's or Charlie's channel, defaulting to `--channel1` / `--p1` / `--q1`) and `--channel-config2`.

### Available channel models

| `--channel1` value         | Description                                          |
|----------------------------|------------------------------------------------------|
| `identity`                 | No-operation; qubits pass through unmodified         |
| `bit-flip`                 | X gate applied with probability p                    |
| `phase-flip`               | Z gate applied with probability p                    |
| `bit-phase-flip`           | Y gate (X + Z) applied with probability p            |
| `depolarizing`             | Qubit replaced with maximally mixed state with probability p |
| `amplitude-damping`        | Energy dissipation (T₁ relaxation) with parameter p  |
| `phase-damping`            | Pure dephasing (T₂ decay) with parameter p           |
| `amplitude-phase-damping`  | Combined T₁ + T₂ decay; requires both `--p1` (p) and `--q1` (λ) |

---

## Channel mix via JSON (`--channel-config`)

Instead of a fixed channel, you can define a **probabilistic mixture** of channels.
Each shot draws one channel at random according to the specified weights.
The channel used is recorded in every output row (`channel_type`, `channel_p`, `channel_q`).

### Format

The config file is a JSON **array** of channel entries:

```json
[
  {
    "type":   "<channel-name>",
    "p":      <noise probability>,
    "q":      <second param, optional, default 0>,
    "weight": <relative weight, optional, default 1>,
    "p_range": [<min>, <max>],
    "p_min":   <min>,
    "p_max":   <max>
  },
  ...
]
```

- `type` — one of the channel names in the table above (e.g. `"bit-flip"`).
- `p` — primary noise probability ∈ [0, 1].
- `q` — second noise parameter, only used for `"amplitude-phase-damping"`.
- `weight` — relative weight for random selection.
- **Ranges**: You can specify a uniform range for `p` or `q` instead of a fixed value. For each shot, a value is sampled uniformly from the interval.
    - `p_range`: `[min, max]` (array)
    - `p_min` / `p_max`: separate fields (also supports `p1_min`/`p1_max` as aliases)
    - `q_range`, `q_min`, `q_max` work identically for the second parameter.

A single-entry array is equivalent to using `--channel` + `--noise`.

### Example

```json
[
  { "type": "bit-flip", "p_range": [0.01, 0.05], "weight": 0.5 },
  { "type": "depolarizing", "p_min": 0.02, "p_max": 0.04, "weight": 0.5 }
]
```

---

## Full Experiment Config (`--experiment-config`)

You can define a full simulation in a single JSON file. This replaces all CLI flags.

### Format

```json
{
  "protocol": "bb84",
  "num_qubits": 1000,
  "shots": 100,
  "seed": 42,
  "out_file": "results.csv",
  "detail": false,

  "channel1": "depolarizing",
  "p1_min": 0.01,
  "p1_max": 0.05,

  "channel_config": [...],

  "eve_ratio": 0.1,
  "check_ratio": 0.5,
  "threshold": 0.9
}
```

### Protocol-specific fields

| Field | Protocols | Description |
|-------|-----------|-------------|
| `num_qubits` | All | Qubits per shot (or rounds for QIA, pairs for BBM92/E91). |
| `shots` | All | Number of independent runs. |
| `channel1` / `p1` / `p1_range` | All | Primary channel model and noise parameters. |
| `channel2` / `p2` / `p2_range` | BBM92, E91, GC01 | Second channel parameters (defaults to `channel1`). |
| `channel_config` | All | Primary channel mix (overrides `channel1`/`p1`). |
| `channel_config2`| BBM92, E91, GC01 | Second channel mix (overrides `channel2`/`p2`). |
| `eve_ratio` | BB84, B92, BBM92, E91, Six-State, SARG04, GC01 | Eve interception probability. |
| `check_ratio` | BB84, B92, BBM92, E91, Six-State, SARG04 | Sifted bits used for QBER. |
| `threshold` | QIA-QZKP, GC01 | Acceptance threshold. |

### Usage

```bash
# Protocol field in the JSON — no subcommand needed
qcryptool --experiment-config my_experiment.json

# Subcommand overrides the JSON protocol field if both are present
qcryptool bb84 --experiment-config my_experiment.json
```

---

## Output formats

### Terminal

A summary is always printed to stdout. With a single shot the full per-run
detail is shown. With multiple shots only the aggregate statistics appear.

### CSV (`-o results.csv`)

One row per shot. Columns: `shot`, `channel_type`, `channel_p`, `channel_q`,
protocol-specific metrics, and (with `--detail`) raw key hex columns.

### JSON (`-o results.json`)

```json
{
  "aggregate": { "protocol": "BB84", "shots": 100, ... },
  "shots": 100,
  "runs": [
    { "shot": 1, "channel_type": "depolarizing", "channel_p": 0.03, ... },
    ...
  ]
}
```

### Plain text (`-o results.txt`)

Human-readable block per shot, followed by aggregate statistics.

---

## Reproducibility

```bash
# These two runs produce identical CSVs
qcryptool bb84 -n 1024 -s 64 --seed 42 -o run_a.csv
qcryptool bb84 -n 1024 -s 64 --seed 42 -o run_b.csv
diff run_a.csv run_b.csv   # empty
```

Internally, shot `i` is seeded with `seed + i`, so individual shots are also
reproducible when run in isolation with `--seed <base + i> -s 1`.

## References

If you use this software in your research or project, please cite it using the information in [CITATION](CITATION.cff). Additionally, if you use the QIA-QZKP protocol in your research, please cite the original paper:

> Garcia-Diaz, J., Escanez-Exposito, D., Caballero-Gil, P. et al. Conjugate coding based designated verifier quantum zero knowledge proof for user authentication. Cryptogr. Commun. (2026). https://doi.org/10.1007/s12095-026-00878-y

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/jorgegardiaz/qcryptool).
