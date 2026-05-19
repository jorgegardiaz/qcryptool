mod channel;
mod config;
mod output;
mod run;
mod stats;

use channel::{ChannelKind, ChannelMix, load_channel_mix, sample_channel, single_channel_mix};
use clap::{Parser, Subcommand};
use config::{ExperimentConfig, load_experiment_config};
use output::{print_terminal, write_file};
use run::execute_shots;

// ── Argument structs ──────────────────────────────────────────────────────────

/// Arguments shared by single-qubit QKD protocols (BB84, B92, Six-State, SARG04).
#[derive(Parser, Debug, Clone)]
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
    #[arg(long, value_enum, default_value = "identity")]
    channel1: ChannelKind,

    /// Channel noise probability p1 ∈ [0,1]; required for any channel except identity (ignored when --channel-config is set)
    #[arg(long)]
    p1: Option<f64>,

    /// Second noise parameter q1 ∈ [0,1]; required only for amplitude-phase-damping (ignored when --channel-config is set)
    #[arg(long)]
    q1: Option<f64>,

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
#[derive(Parser, Debug, Clone)]
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

    /// Quantum channel model for Alice (ignored when --channel-config1 is set)
    #[arg(long, value_enum, default_value = "identity")]
    channel1: ChannelKind,

    /// Channel noise for Alice p1 ∈ [0,1]; required for any channel except identity (ignored when --channel-config1 is set)
    #[arg(long)]
    p1: Option<f64>,

    /// Second noise parameter for Alice q1 ∈ [0,1]; required only for amplitude-phase-damping (ignored when --channel-config1 is set)
    #[arg(long)]
    q1: Option<f64>,

    /// JSON file defining a channel mix for Alice; each shot samples one channel
    #[arg(long, value_name = "FILE")]
    channel_config1: Option<String>,

    /// Quantum channel model for Bob; defaults to --channel1 (ignored when --channel-config2 is set)
    #[arg(long, value_enum)]
    channel2: Option<ChannelKind>,

    /// Channel noise for Bob p2 ∈ [0,1]; defaults to --p1 (ignored when --channel-config2 is set)
    #[arg(long)]
    p2: Option<f64>,

    /// Second noise parameter for Bob q2 ∈ [0,1]; defaults to --q1 (ignored when --channel-config2 is set)
    #[arg(long)]
    q2: Option<f64>,

    /// JSON file defining a channel mix for Bob; defaults to --channel-config1 if not set
    #[arg(long, value_name = "FILE")]
    channel_config2: Option<String>,

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
#[derive(Parser, Debug, Clone)]
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
    #[arg(long, value_enum, default_value = "identity")]
    channel1: ChannelKind,

    /// Channel noise probability p1 ∈ [0,1]; required for any channel except identity (ignored when --channel-config is set)
    #[arg(long)]
    p1: Option<f64>,

    /// Second noise parameter q1 ∈ [0,1]; required only for amplitude-phase-damping (ignored when --channel-config is set)
    #[arg(long)]
    q1: Option<f64>,

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

/// Arguments for GC01 Quantum Digital Signature protocol.
#[derive(Parser, Debug, Clone)]
pub struct QdsArgs {
    /// Length of each public key (qubits per message value)
    #[arg(short = 'n', long, default_value_t = 200)]
    num_qubits: usize,

    /// Number of times to run the protocol
    #[arg(short = 's', long, default_value_t = 1)]
    shots: usize,

    /// Save results to file (.json / .csv / .txt)
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Quantum channel model for Bob (ignored when --channel-config is set)
    #[arg(long, value_enum, default_value = "identity")]
    channel1: ChannelKind,

    /// Channel noise probability for Bob p1 ∈ [0,1]; required for any channel except identity (ignored when --channel-config is set)
    #[arg(long)]
    p1: Option<f64>,

    /// Second noise parameter for Bob q1 ∈ [0,1]; required only for amplitude-phase-damping (ignored when --channel-config is set)
    #[arg(long)]
    q1: Option<f64>,

    /// JSON file defining a channel mix for Bob; each shot samples one channel
    #[arg(long, value_name = "FILE")]
    channel_config: Option<String>,

    /// Quantum channel model for Charlie; defaults to --channel1 (ignored when --channel-config2 is set)
    #[arg(long, value_enum)]
    channel2: Option<ChannelKind>,

    /// Channel noise for Charlie p2 ∈ [0,1]; defaults to --p1 (ignored when --channel-config2 is set)
    #[arg(long)]
    p2: Option<f64>,

    /// Second noise parameter for Charlie q2 ∈ [0,1]; defaults to --q1 (ignored when --channel-config2 is set)
    #[arg(long)]
    q2: Option<f64>,

    /// JSON file defining a channel mix for Charlie; defaults to --channel-config if not set
    #[arg(long, value_name = "FILE")]
    channel_config2: Option<String>,

    /// Probability of Eve intercepting each qubit ∈ [0,1]
    #[arg(long, default_value_t = 0.0)]
    eve_ratio: f64,

    /// Maximum SWAP-test failure rate for signature acceptance ∈ [0,1]
    #[arg(long, default_value_t = 0.1)]
    threshold: f64,

    /// RNG seed for reproducible simulations (each shot uses seed+i)
    #[arg(long)]
    seed: Option<u64>,
}

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "qcryptool",
    about = "Simulator for quantum cryptography protocols (powered by qcrypto)",
    version
)]
struct Cli {
    /// JSON file with a full experiment configuration (replaces all other flags when set)
    #[arg(long, global = true, value_name = "FILE")]
    experiment_config: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
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
    /// GC01 QDS — Gottesman-Chuang (2001) Quantum Digital Signature
    Gc01(QdsArgs),
}

impl Command {
    pub fn as_str(&self) -> &'static str {
        match self {
            Command::Bb84(_) => "bb84",
            Command::B92(_) => "b92",
            Command::Bbm92(_) => "bbm92",
            Command::E91(_) => "e91",
            Command::SixState(_) => "six-state",
            Command::Sarg04(_) => "sarg04",
            Command::QiaQzkp(_) => "qia-qzkp",
            Command::Gc01(_) => "gc01",
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn resolve_mix(
    config: &Option<String>,
    kind: &ChannelKind,
    p: Option<f64>,
    q: Option<f64>,
) -> ChannelMix {
    match config {
        Some(path) => load_channel_mix(path).unwrap_or_else(|e| {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }),
        None => single_channel_mix(kind, p, q),
    }
}

// ── Execution logic ───────────────────────────────────────────────────────────

fn execute_from_config(protocol: &str, cfg: ExperimentConfig, cmd: Option<Command>) {
    match protocol.to_lowercase().as_str() {
        "bb84" => {
            let a = match cmd {
                Some(Command::Bb84(args)) => args,
                _ => QkdArgs::parse_from(["qcryptool"]),
            };
            let mix = cfg.primary_mix();
            let shots = cfg.shots.unwrap_or(a.shots);
            let seed = cfg.seed.or(a.seed);
            let output = cfg.out_file.clone().or(a.output);
            let detail = cfg.detail.unwrap_or(a.detail);
            let keys_out = cfg.keys_out.unwrap_or(detail);
            let n = cfg.num_qubits.unwrap_or(a.num_qubits);
            let eve = cfg.eve_ratio.unwrap_or(a.eve_ratio);
            let check = cfg.check_ratio.unwrap_or(a.check_ratio);
            let runs = execute_shots(shots, seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_bb84(i, n, &ch, info, eve, check, detail || keys_out, par)
            });
            if let Some(ref p) = output {
                write_file(p, &runs, keys_out);
            }
            print_terminal(&runs, shots, detail);
        }
        "b92" => {
            let a = match cmd {
                Some(Command::B92(args)) => args,
                _ => QkdArgs::parse_from(["qcryptool"]),
            };
            let mix = cfg.primary_mix();
            let shots = cfg.shots.unwrap_or(a.shots);
            let seed = cfg.seed.or(a.seed);
            let output = cfg.out_file.clone().or(a.output);
            let detail = cfg.detail.unwrap_or(a.detail);
            let keys_out = cfg.keys_out.unwrap_or(detail);
            let n = cfg.num_qubits.unwrap_or(a.num_qubits);
            let eve = cfg.eve_ratio.unwrap_or(a.eve_ratio);
            let check = cfg.check_ratio.unwrap_or(a.check_ratio);
            let runs = execute_shots(shots, seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_b92(i, n, &ch, info, eve, check, detail || keys_out, par)
            });
            if let Some(ref p) = output {
                write_file(p, &runs, keys_out);
            }
            print_terminal(&runs, shots, detail);
        }
        "bbm92" => {
            let a = match cmd {
                Some(Command::Bbm92(args)) => args,
                _ => EntangleArgs::parse_from(["qcryptool"]),
            };
            let mix_a = cfg.primary_mix();
            let mix_b = cfg.secondary_mix();
            let shots = cfg.shots.unwrap_or(a.shots);
            let seed = cfg.seed.or(a.seed);
            let output = cfg.out_file.clone().or(a.output);
            let detail = cfg.detail.unwrap_or(a.detail);
            let keys_out = cfg.keys_out.unwrap_or(detail);
            let n = cfg.num_qubits.unwrap_or(a.num_pairs);
            let eve = cfg.eve_ratio.unwrap_or(a.eve_ratio);
            let check = cfg.check_ratio.unwrap_or(a.check_ratio);
            let runs = execute_shots(shots, seed, |i, par| {
                let (ch_a, info_a) = sample_channel(&mix_a);
                let (ch_b, info_b) = sample_channel(&mix_b);
                run::run_bbm92(
                    i,
                    n,
                    &ch_a,
                    &ch_b,
                    info_a,
                    info_b,
                    eve,
                    check,
                    detail || keys_out,
                    par,
                )
            });
            if let Some(ref p) = output {
                write_file(p, &runs, keys_out);
            }
            print_terminal(&runs, shots, detail);
        }
        "e91" => {
            let a = match cmd {
                Some(Command::E91(args)) => args,
                _ => EntangleArgs::parse_from(["qcryptool"]),
            };
            let mix_a = cfg.primary_mix();
            let mix_b = cfg.secondary_mix();
            let shots = cfg.shots.unwrap_or(a.shots);
            let seed = cfg.seed.or(a.seed);
            let output = cfg.out_file.clone().or(a.output);
            let detail = cfg.detail.unwrap_or(a.detail);
            let keys_out = cfg.keys_out.unwrap_or(detail);
            let n = cfg.num_qubits.unwrap_or(a.num_pairs);
            let eve = cfg.eve_ratio.unwrap_or(a.eve_ratio);
            let check = cfg.check_ratio.unwrap_or(a.check_ratio);
            let runs = execute_shots(shots, seed, |i, par| {
                let (ch_a, info_a) = sample_channel(&mix_a);
                let (ch_b, info_b) = sample_channel(&mix_b);
                run::run_e91(
                    i,
                    n,
                    &ch_a,
                    &ch_b,
                    info_a,
                    info_b,
                    eve,
                    check,
                    detail || keys_out,
                    par,
                )
            });
            if let Some(ref p) = output {
                write_file(p, &runs, keys_out);
            }
            print_terminal(&runs, shots, detail);
        }
        "six-state" => {
            let a = match cmd {
                Some(Command::SixState(args)) => args,
                _ => QkdArgs::parse_from(["qcryptool"]),
            };
            let mix = cfg.primary_mix();
            let shots = cfg.shots.unwrap_or(a.shots);
            let seed = cfg.seed.or(a.seed);
            let output = cfg.out_file.clone().or(a.output);
            let detail = cfg.detail.unwrap_or(a.detail);
            let keys_out = cfg.keys_out.unwrap_or(detail);
            let n = cfg.num_qubits.unwrap_or(a.num_qubits);
            let eve = cfg.eve_ratio.unwrap_or(a.eve_ratio);
            let check = cfg.check_ratio.unwrap_or(a.check_ratio);
            let runs = execute_shots(shots, seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_six_state(i, n, &ch, info, eve, check, detail || keys_out, par)
            });
            if let Some(ref p) = output {
                write_file(p, &runs, keys_out);
            }
            print_terminal(&runs, shots, detail);
        }
        "sarg04" => {
            let a = match cmd {
                Some(Command::Sarg04(args)) => args,
                _ => QkdArgs::parse_from(["qcryptool"]),
            };
            let mix = cfg.primary_mix();
            let shots = cfg.shots.unwrap_or(a.shots);
            let seed = cfg.seed.or(a.seed);
            let output = cfg.out_file.clone().or(a.output);
            let detail = cfg.detail.unwrap_or(a.detail);
            let keys_out = cfg.keys_out.unwrap_or(detail);
            let n = cfg.num_qubits.unwrap_or(a.num_qubits);
            let eve = cfg.eve_ratio.unwrap_or(a.eve_ratio);
            let check = cfg.check_ratio.unwrap_or(a.check_ratio);
            let runs = execute_shots(shots, seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_sarg04(i, n, &ch, info, eve, check, detail || keys_out, par)
            });
            if let Some(ref p) = output {
                write_file(p, &runs, keys_out);
            }
            print_terminal(&runs, shots, detail);
        }
        "qia-qzkp" => {
            let a = match cmd {
                Some(Command::QiaQzkp(args)) => args,
                _ => QiaQzkpArgs::parse_from(["qcryptool"]),
            };
            let mix = cfg.primary_mix();
            let shots = cfg.shots.unwrap_or(a.shots);
            let seed = cfg.seed.or(a.seed);
            let output = cfg.out_file.clone().or(a.output);
            let detail = cfg.detail.unwrap_or(a.detail);
            let keys_out = cfg.keys_out.unwrap_or(detail);
            let n = cfg.num_qubits.unwrap_or(a.num_qubits);
            let threshold = cfg.threshold.unwrap_or(a.threshold);
            let runs = execute_shots(shots, seed, |i, par| {
                let (ch, info) = sample_channel(&mix);
                run::run_qia_qzkp(i, n, &ch, info, threshold, detail || keys_out, par)
            });
            if let Some(ref p) = output {
                write_file(p, &runs, keys_out);
            }
            print_terminal(&runs, shots, detail);
        }
        "gc01" => {
            let a = match cmd {
                Some(Command::Gc01(args)) => args,
                _ => QdsArgs::parse_from(["qcryptool"]),
            };
            let mix_bob = cfg.primary_mix();
            let mix_charlie = cfg.secondary_mix();
            let shots = cfg.shots.unwrap_or(a.shots);
            let seed = cfg.seed.or(a.seed);
            let output = cfg.out_file.clone().or(a.output);
            let n = cfg.num_qubits.unwrap_or(a.num_qubits);
            let eve = cfg.eve_ratio.unwrap_or(a.eve_ratio);
            let threshold = cfg.threshold.unwrap_or(a.threshold);
            let runs = execute_shots(shots, seed, |i, par| {
                let (ch_bob, info_bob) = sample_channel(&mix_bob);
                let (ch_charlie, info_charlie) = sample_channel(&mix_charlie);
                run::run_gc01(
                    i,
                    n,
                    &ch_bob,
                    &ch_charlie,
                    info_bob,
                    info_charlie,
                    eve,
                    threshold,
                    par,
                )
            });
            if let Some(ref p) = output {
                write_file(p, &runs, cfg.keys_out.unwrap_or(false));
            }
            print_terminal(&runs, shots, false);
        }
        other => {
            eprintln!("Error: unknown protocol '{other}'");
            std::process::exit(1);
        }
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
        let mix = resolve_mix(&None, &ChannelKind::Depolarizing, Some(0.05), None);
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
            None,
            None,
        );
        assert_eq!(mix.len(), 1);
        assert_eq!(mix[0].kind, "phase-flip");
        assert!((mix[0].p - 0.02).abs() < 1e-12);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    if let Some(path) = cli.experiment_config {
        let config = load_experiment_config(&path);
        let protocol = config.protocol.clone().or_else(|| {
            cli.command.as_ref().map(|c| c.as_str().to_string())
        }).unwrap_or_else(|| {
            eprintln!("Error: 'protocol' field is required in experiment config when no subcommand is used");
            std::process::exit(1);
        });

        if let (Some(p_json), Some(cmd)) = (&config.protocol, &cli.command)
            && p_json.to_lowercase() != cmd.as_str().to_lowercase()
        {
            eprintln!(
                "Warning: experiment config protocol '{p_json}' does not match subcommand '{}'",
                cmd.as_str()
            );
        }

        execute_from_config(&protocol, config, cli.command);
    } else {
        match cli.command {
            Some(Command::Bb84(a)) => {
                let mix = resolve_mix(&a.channel_config, &a.channel1, a.p1, a.q1);
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
                if let Some(ref p) = a.output {
                    write_file(p, &runs, a.detail);
                }
                print_terminal(&runs, a.shots, a.detail);
            }
            Some(Command::B92(a)) => {
                let mix = resolve_mix(&a.channel_config, &a.channel1, a.p1, a.q1);
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
                if let Some(ref p) = a.output {
                    write_file(p, &runs, a.detail);
                }
                print_terminal(&runs, a.shots, a.detail);
            }
            Some(Command::Bbm92(a)) => {
                let mix_a = resolve_mix(&a.channel_config1, &a.channel1, a.p1, a.q1);
                let ch_b = a.channel2.as_ref().unwrap_or(&a.channel1);
                let cfg_b = a
                    .channel_config2
                    .clone()
                    .or_else(|| a.channel_config1.clone());
                let mix_b = resolve_mix(&cfg_b, ch_b, a.p2.or(a.p1), a.q2.or(a.q1));
                let runs = execute_shots(a.shots, a.seed, |i, par| {
                    let (ch_a, info_a) = sample_channel(&mix_a);
                    let (ch_b, info_b) = sample_channel(&mix_b);
                    run::run_bbm92(
                        i,
                        a.num_pairs,
                        &ch_a,
                        &ch_b,
                        info_a,
                        info_b,
                        a.eve_ratio,
                        a.check_ratio,
                        a.detail,
                        par,
                    )
                });
                if let Some(ref p) = a.output {
                    write_file(p, &runs, a.detail);
                }
                print_terminal(&runs, a.shots, a.detail);
            }
            Some(Command::E91(a)) => {
                let mix_a = resolve_mix(&a.channel_config1, &a.channel1, a.p1, a.q1);
                let ch_b = a.channel2.as_ref().unwrap_or(&a.channel1);
                let cfg_b = a
                    .channel_config2
                    .clone()
                    .or_else(|| a.channel_config1.clone());
                let mix_b = resolve_mix(&cfg_b, ch_b, a.p2.or(a.p1), a.q2.or(a.q1));
                let runs = execute_shots(a.shots, a.seed, |i, par| {
                    let (ch_a, info_a) = sample_channel(&mix_a);
                    let (ch_b, info_b) = sample_channel(&mix_b);
                    run::run_e91(
                        i,
                        a.num_pairs,
                        &ch_a,
                        &ch_b,
                        info_a,
                        info_b,
                        a.eve_ratio,
                        a.check_ratio,
                        a.detail,
                        par,
                    )
                });
                if let Some(ref p) = a.output {
                    write_file(p, &runs, a.detail);
                }
                print_terminal(&runs, a.shots, a.detail);
            }
            Some(Command::SixState(a)) => {
                let mix = resolve_mix(&a.channel_config, &a.channel1, a.p1, a.q1);
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
                if let Some(ref p) = a.output {
                    write_file(p, &runs, a.detail);
                }
                print_terminal(&runs, a.shots, a.detail);
            }
            Some(Command::Sarg04(a)) => {
                let mix = resolve_mix(&a.channel_config, &a.channel1, a.p1, a.q1);
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
                if let Some(ref p) = a.output {
                    write_file(p, &runs, a.detail);
                }
                print_terminal(&runs, a.shots, a.detail);
            }
            Some(Command::QiaQzkp(a)) => {
                let mix = resolve_mix(&a.channel_config, &a.channel1, a.p1, a.q1);
                let runs = execute_shots(a.shots, a.seed, |i, par| {
                    let (ch, info) = sample_channel(&mix);
                    run::run_qia_qzkp(i, a.num_qubits, &ch, info, a.threshold, a.detail, par)
                });
                if let Some(ref p) = a.output {
                    write_file(p, &runs, a.detail);
                }
                print_terminal(&runs, a.shots, a.detail);
            }
            Some(Command::Gc01(a)) => {
                let mix_bob = resolve_mix(&a.channel_config, &a.channel1, a.p1, a.q1);
                let ch_c = a.channel2.as_ref().unwrap_or(&a.channel1);
                let cfg_c = a
                    .channel_config2
                    .clone()
                    .or_else(|| a.channel_config.clone());
                let mix_charlie = resolve_mix(&cfg_c, ch_c, a.p2.or(a.p1), a.q2.or(a.q1));
                let runs = execute_shots(a.shots, a.seed, |i, par| {
                    let (ch_bob, info_bob) = sample_channel(&mix_bob);
                    let (ch_charlie, info_charlie) = sample_channel(&mix_charlie);
                    run::run_gc01(
                        i,
                        a.num_qubits,
                        &ch_bob,
                        &ch_charlie,
                        info_bob,
                        info_charlie,
                        a.eve_ratio,
                        a.threshold,
                        par,
                    )
                });
                if let Some(ref p) = a.output {
                    write_file(p, &runs, false);
                }
                print_terminal(&runs, a.shots, false);
            }
            None => {
                use clap::CommandFactory;
                Cli::command().print_help().unwrap();
                println!();
            }
        }
    }
}
