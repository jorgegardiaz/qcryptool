<div align="center">

  <h1>qcryptool</h1>
  
  <p>
    <strong>A Pure Rust Framework for Quantum Cryptography Simulation</strong>
  </p>

  <img src="./assets/qcrypto_logo.png" alt="qcrypto logo" width="150">
    
  [![Pure Rust](https://img.shields.io/badge/Pure-Rust-orange)](https://www.rust-lang.org)
  [![Crates.io](https://img.shields.io/crates/v/qcryptool.svg)](https://crates.io/crates/qcryptool)
  [![Docs](https://docs.rs/qcryptool/badge.svg)](https://docs.rs/qcrypto)
  [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
  [![Rust CI](https://github.com/jorgegardiaz/qcryptool/actions/workflows/test.yml/badge.svg)](https://github.com/jorgegardiaz/qcryptool/actions/workflows/test.yml)
  ![Coverage](https://raw.githubusercontent.com/jorgegardiaz/qcryptool/master/.github/badges/coverage.svg)


</div>

CLI simulator for quantum cryptography protocols, powered by [qcrypto](https://github.com/jorgegardiaz/qcrypto).

## Building

```bash
cargo build --release
```

The binary is placed at `target/release/qcryptool`.

---

## Protocols

| Subcommand   | Protocol                                      |
|--------------|-----------------------------------------------|
| `bb84`       | BB84 — Bennett & Brassard (1984)              |
| `b92`        | B92 — Bennett (1992)                          |
| `bbm92`      | BBM92 — entanglement-based BB84               |
| `e91`        | E91 — Ekert (1991), Bell inequality test      |
| `six-state`  | Six-State — Pasquinucci & Gisin (1999)        |
| `sarg04`     | SARG04 — Scarani, Acín, Ribordy & Gisin (2004)|
| `qia-qzkp`   | QIA-QZKP — Quantum Identity Authentication   |

---

## Basic usage

```bash
# Single shot, default channel (bit-flip, no noise)
qcryptool bb84 -n 1000

# 100 shots, depolarizing noise p=0.03, save to CSV
qcryptool bb84 -n 1024 -s 100 --channel depolarizing --noise 0.03 -o results.csv

# Entanglement-based with asymmetric noise
qcryptool bbm92 -n 1000 --noise 0.01 --noise-bob 0.04

# Reproducible run (each shot uses seed + i)
qcryptool bb84 -n 1000 -s 50 --seed 42 -o out.csv

# Include key hex in output
qcryptool bb84 -n 512 --detail
```

### Common flags (all protocols)

| Flag | Description |
|------|-------------|
| `-n` / `--num-qubits` | Qubits / pairs / rounds per shot |
| `-s` / `--shots` | Number of independent runs |
| `-o` / `--output` | Output file (`.json`, `.csv`, or `.txt`) |
| `--channel` | Channel model (see table below) |
| `--noise` | Primary noise probability p ∈ [0, 1] |
| `--noise2` | Second noise parameter (amplitude-phase-damping only) |
| `--channel-config` | JSON file with a channel mix (overrides `--channel`/`--noise`) |
| `--eve-ratio` | Probability of Eve intercepting each qubit |
| `--check-ratio` | Fraction of sifted bits used for QBER estimation |
| `--seed` | RNG seed for reproducible simulations |
| `--detail` | Include raw keys/vectors in the output |

### Available channel models

| `--channel` value          | Description                                     |
|----------------------------|-------------------------------------------------|
| `bit-flip`                 | Bit-flip error with probability p               |
| `phase-flip`               | Phase-flip error with probability p             |
| `bit-phase-flip`           | Combined bit+phase flip with probability p      |
| `depolarizing`             | Depolarizing noise with probability p           |
| `amplitude-damping`        | Energy dissipation (T1 decay) with parameter p  |
| `phase-damping`            | Pure dephasing (T2 decay) with parameter p      |
| `amplitude-phase-damping`  | Combined T1+T2; uses `--noise` (p) and `--noise2` (λ) |

---

## Channel mix via JSON (`--channel-config`)

Instead of a fixed channel, you can define a **probabilistic mixture** of channels.
Each shot draws one channel at random according to the specified weights.
The channel used is recorded in every output row (`channel_type`, `channel_p`, `channel_p2`).

### Format

The config file is a JSON **array** of channel entries:

```json
[
  {
    "type":   "<channel-name>",
    "p":      <noise probability>,
    "p2":     <second param, optional, default 0>,
    "weight": <relative weight, optional, default 1>
  },
  ...
]
```

- `type` — one of the channel names in the table above (e.g. `"bit-flip"`).
- `p` — primary noise probability ∈ [0, 1].
- `p2` — second noise parameter, only used for `"amplitude-phase-damping"`.
- `weight` — relative weight for random selection. Weights do **not** need to sum to 1; they are normalised internally. Omit to give all channels equal weight.

A single-entry array is equivalent to using `--channel` + `--noise`.

### Example

```json
[
  { "type": "bit-flip",               "p": 0.01,             "weight": 0.50 },
  { "type": "depolarizing",           "p": 0.03,             "weight": 0.30 },
  { "type": "amplitude-damping",      "p": 0.05,             "weight": 0.15 },
  { "type": "amplitude-phase-damping","p": 0.04, "p2": 0.02, "weight": 0.05 }
]
```

A ready-to-use copy of this example is at `channel_config_example.json`.

### Usage

```bash
# 200 shots, channel sampled each shot from the mix
qcryptool bb84 -n 1024 -s 200 --channel-config channel_config_example.json -o results.csv

# Reproducible with seed
qcryptool bb84 -n 1024 -s 200 --channel-config channel_config_example.json --seed 7 -o results.csv
```

### Output columns added

When `--channel-config` is used (or even with plain `--channel`), every CSV row
and JSON run entry includes:

| Field          | Description                                   |
|----------------|-----------------------------------------------|
| `channel_type` | Name of the channel used in this shot         |
| `channel_p`    | Primary noise parameter p                     |
| `channel_p2`   | Second noise parameter (0 when not applicable)|

For **BBM92** and **E91**, Alice and Bob each sample their channel independently
from the same distribution. The recorded `channel_type`/`channel_p` correspond
to Alice's channel.

### Notes

- When `--channel-config` is set, `--channel`, `--noise`, and `--noise2` are ignored.
- For **BBM92**/**E91**, `--noise-bob` is also ignored; use the mix instead.
- Channel selection is part of the RNG stream, so `--seed` guarantees full
  reproducibility including which channel each shot uses.

---

## Output formats

### Terminal

A summary is always printed to stdout. With a single shot the full per-run
detail is shown. With multiple shots only the aggregate statistics appear.

### CSV (`-o results.csv`)

One row per shot. Columns: `shot`, `channel_type`, `channel_p`, `channel_p2`,
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
