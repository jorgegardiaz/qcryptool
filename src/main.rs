mod channel;
mod output;
mod run;
mod stats;

use channel::{ChannelKind, ChannelMix, load_channel_mix, sample_channel, single_channel_mix};
use clap::{Args, Parser, Subcommand};
use output::{print_terminal, write_file};
use run::execute_shots;

// ── Argument structs ──────────────────────────────────────────────────────────

/// Arguments shared by single-qubit QKD protocols (BB84, B92, Six-State, SARG04).
#[derive(Args, Debug)]
pub struct QkdArgs {
    /// Number of qubits to transmit per shot
    #[arg(short = 'n', long, default_value_t = 1000)]
    num_qubits: usize,

    /// Number of times to run the protocol
    #[arg(short = 's', long, default_value_t = 1)]
    shots: usize,

    /// Save results to file (.json / .csv / .txt)
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Quantum channel model (ignored when --channel-config is set)
    #[arg(long, value_enum, default_value = "bit-flip")]
    channel: ChannelKind,

    /// Channel noise probability p ∈ [0,1] (ignored when --channel-config is set)
    #[arg(long, default_value_t = 0.0)]
    noise: f64,

    /// Second noise parameter λ ∈ [0,1] (only for --channel amplitude-phase-damping)
    #[arg(long, default_value_t = 0.0)]
    noise2: f64,

    /// JSON file defining a channel mix; each shot samples one channel from it
    #[arg(long, value_name = "FILE")]
    channel_config: Option<String>,

    /// Probability of Eve intercepting each qubit ∈ [0,1]
    #[arg(long, default_value_t = 0.0)]
    eve_ratio: f64,

    /// Fraction of sifted bits sacrificed for QBER estimation ∈ [0,1]
    #[arg(long, default_value_t = 0.5)]
    check_ratio: f64,

    /// RNG seed for reproducible simulations (each shot uses seed+i)
    #[arg(long)]
    seed: Option<u64>,

    /// Include keys in output: shots=1 shows them in terminal, shots>1 adds columns to the output file
    #[arg(long)]
    detail: bool,
}

/// Arguments for entanglement-based protocols (BBM92, E91).
#[derive(Args, Debug)]
pub struct EntangleArgs {
    /// Number of entangled pairs to distribute per shot
    #[arg(short = 'n', long, default_value_t = 1000)]
    num_pairs: usize,

    /// Number of times to run the protocol
    #[arg(short = 's', long, default_value_t = 1)]
    shots: usize,

    /// Save results to file (.json / .csv / .txt)
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Quantum channel model applied to both Alice and Bob (ignored when --channel-config is set)
    #[arg(long, value_enum, default_value = "bit-flip")]
    channel: ChannelKind,

    /// Channel noise for Alice ∈ [0,1] (ignored when --channel-config is set)
    #[arg(long, default_value_t = 0.0)]
    noise: f64,

    /// Channel noise for Bob ∈ [0,1]; defaults to --noise (ignored when --channel-config is set)
    #[arg(long)]
    noise_bob: Option<f64>,

    /// Second noise parameter λ ∈ [0,1] (only for --channel amplitude-phase-damping)
    #[arg(long, default_value_t = 0.0)]
    noise2: f64,

    /// JSON file defining a channel mix; each shot samples one channel independently for Alice and Bob
    #[arg(long, value_name = "FILE")]
    channel_config: Option<String>,

    /// Probability of Eve intercepting Bob's qubit ∈ [0,1]
    #[arg(long, default_value_t = 0.0)]
    eve_ratio: f64,

    /// Fraction of sifted bits sacrificed for QBER estimation ∈ [0,1]
    #[arg(long, default_value_t = 0.5)]
    check_ratio: f64,

    /// RNG seed for reproducible simulations (each shot uses seed+i)
    #[arg(long)]
    seed: Option<u64>,

    /// Include keys in output: shots=1 shows them in terminal, shots>1 adds columns to the output file
    #[arg(long)]
    detail: bool,
}

/// Arguments for QIA-QZKP.
#[derive(Args, Debug)]
pub struct QiaQzkpArgs {
    /// Number of protocol rounds per shot
    #[arg(short = 'n', long, default_value_t = 100)]
    num_qubits: usize,

    /// Number of times to run the protocol
    #[arg(short = 's', long, default_value_t = 1)]
    shots: usize,

    /// Save results to file (.json / .csv / .txt)
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Quantum channel model (ignored when --channel-config is set)
    #[arg(long, value_enum, default_value = "bit-flip")]
    channel: ChannelKind,

    /// Channel noise probability p ∈ [0,1] (ignored when --channel-config is set)
    #[arg(long, default_value_t = 0.0)]
    noise: f64,

    /// Second noise parameter q ∈ [0,1] (only for --channel amplitude-phase-damping)
    #[arg(long, default_value_t = 0.0)]
    noise2: f64,

    /// JSON file defining a channel mix; each shot samples one channel from it
    #[arg(long, value_name = "FILE")]
    channel_config: Option<String>,

    /// Minimum match accuracy required for authentication k ∈ [0,1]
    #[arg(long, default_value_t = 0.9)]
    threshold: f64,

    /// RNG seed for reproducible simulations (each shot uses seed+i)
    #[arg(long)]
    seed: Option<u64>,

    /// Include identity/commitment vectors in output: shots=1 shows them in terminal, shots>1 adds columns to the output file
    #[arg(long)]
    detail: bool,
}

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "qcryptool",
    about = "Simulator for quantum cryptography protocols (powered by qcrypto)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// BB84 QKD — Bennett & Brassard (1984), two conjugate bases
    Bb84(QkdArgs),
    /// B92 QKD — Bennett (1992), two non-orthogonal states
    B92(QkdArgs),
    /// BBM92 QKD — Bennett, Brassard & Mermin (1992), entanglement-based BB84
    Bbm92(EntangleArgs),
    /// E91 QKD — Ekert (1991), entanglement + Bell inequality test
    E91(EntangleArgs),
    /// Six-State QKD — Pasquinucci & Gisin (1999), three mutually unbiased bases
    #[command(name = "six-state")]
    SixState(QkdArgs),
    /// SARG04 QKD — Scarani, Acín, Ribordy & Gisin (2004)
    Sarg04(QkdArgs),
    /// QIA-QZKP — Quantum Identity Authentication via Zero-Knowledge Proof
    #[command(name = "qia-qzkp")]
    QiaQzkp(QiaQzkpArgs),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn resolve_mix(config: &Option<String>, kind: &ChannelKind, p: f64, p2: f64) -> ChannelMix {
    match config {
        Some(path) => load_channel_mix(path).unwrap_or_else(|e| {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }),
        None => single_channel_mix(kind, p, p2),
    }
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn resolve_mix_no_config_uses_cli_args() {
        let mix = resolve_mix(&None, &ChannelKind::Depolarizing, 0.05, 0.0);
        assert_eq!(mix.len(), 1);
        assert_eq!(mix[0].kind, "depolarizing");
        assert!((mix[0].p - 0.05).abs() < 1e-12);
    }

    #[test]
    fn resolve_mix_with_valid_config_file() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"[{{"type":"phase-flip","p":0.02}}]"#).unwrap();
        let mix = resolve_mix(
            &Some(f.path().to_str().unwrap().to_string()),
            &ChannelKind::BitFlip,
            0.0,
            0.0,
        );
        assert_eq!(mix.len(), 1);
        assert_eq!(mix[0].kind, "phase-flip");
        assert!((mix[0].p - 0.02).abs() < 1e-12);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Command::Bb84(a) => {
            let mix = resolve_mix(&a.channel_config, &a.channel, a.noise, a.noise2);
            let runs = execute_shots(a.shots, a.seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_bb84(
                    i,
                    a.num_qubits,
                    &ch,
                    info,
                    a.eve_ratio,
                    a.check_ratio,
                    a.detail,
                    par,
                )
            });
            if let Some(p) = &a.output {
                write_file(p, &runs, a.detail);
            }
            print_terminal(&runs, a.shots, a.detail);
        }
        Command::B92(a) => {
            let mix = resolve_mix(&a.channel_config, &a.channel, a.noise, a.noise2);
            let runs = execute_shots(a.shots, a.seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_b92(
                    i,
                    a.num_qubits,
                    &ch,
                    info,
                    a.eve_ratio,
                    a.check_ratio,
                    a.detail,
                    par,
                )
            });
            if let Some(p) = &a.output {
                write_file(p, &runs, a.detail);
            }
            print_terminal(&runs, a.shots, a.detail);
        }
        Command::Bbm92(a) => {
            let mix = resolve_mix(&a.channel_config, &a.channel, a.noise, a.noise2);
            let runs = execute_shots(a.shots, a.seed, |i, par| {
                let (ch_a, info_a) = sample_channel(&mix);
                let (ch_b, _) = sample_channel(&mix);
                run::run_bbm92(
                    i,
                    a.num_pairs,
                    &ch_a,
                    &ch_b,
                    info_a,
                    a.eve_ratio,
                    a.check_ratio,
                    a.detail,
                    par,
                )
            });
            if let Some(p) = &a.output {
                write_file(p, &runs, a.detail);
            }
            print_terminal(&runs, a.shots, a.detail);
        }
        Command::E91(a) => {
            let mix = resolve_mix(&a.channel_config, &a.channel, a.noise, a.noise2);
            let runs = execute_shots(a.shots, a.seed, |i, par| {
                let (ch_a, info_a) = sample_channel(&mix);
                let (ch_b, _) = sample_channel(&mix);
                run::run_e91(
                    i,
                    a.num_pairs,
                    &ch_a,
                    &ch_b,
                    info_a,
                    a.eve_ratio,
                    a.check_ratio,
                    a.detail,
                    par,
                )
            });
            if let Some(p) = &a.output {
                write_file(p, &runs, a.detail);
            }
            print_terminal(&runs, a.shots, a.detail);
        }
        Command::SixState(a) => {
            let mix = resolve_mix(&a.channel_config, &a.channel, a.noise, a.noise2);
            let runs = execute_shots(a.shots, a.seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_six_state(
                    i,
                    a.num_qubits,
                    &ch,
                    info,
                    a.eve_ratio,
                    a.check_ratio,
                    a.detail,
                    par,
                )
            });
            if let Some(p) = &a.output {
                write_file(p, &runs, a.detail);
            }
            print_terminal(&runs, a.shots, a.detail);
        }
        Command::Sarg04(a) => {
            let mix = resolve_mix(&a.channel_config, &a.channel, a.noise, a.noise2);
            let runs = execute_shots(a.shots, a.seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_sarg04(
                    i,
                    a.num_qubits,
                    &ch,
                    info,
                    a.eve_ratio,
                    a.check_ratio,
                    a.detail,
                    par,
                )
            });
            if let Some(p) = &a.output {
                write_file(p, &runs, a.detail);
            }
            print_terminal(&runs, a.shots, a.detail);
        }
        Command::QiaQzkp(a) => {
            let mix = resolve_mix(&a.channel_config, &a.channel, a.noise, a.noise2);
            let runs = execute_shots(a.shots, a.seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_qia_qzkp(i, a.num_qubits, &ch, info, a.threshold, a.detail, par)
            });
            if let Some(p) = &a.output {
                write_file(p, &runs, a.detail);
            }
            print_terminal(&runs, a.shots, a.detail);
        }
    }
}
