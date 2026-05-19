use clap::ValueEnum;
use qcrypto::QuantumChannel;
use serde::Deserialize;

// ── CLI channel (legacy single-channel flags) ─────────────────────────────────

#[derive(Clone, Debug, ValueEnum)]
pub enum ChannelKind {
    /// No-operation channel; qubits pass through unmodified.
    Identity,
    /// Bit-flip channel; applies an X gate with probability `--p1`.
    BitFlip,
    /// Phase-flip channel; applies a Z gate with probability `--p1`.
    PhaseFlip,
    /// Bit-phase-flip channel; applies a Y gate (X followed by Z) with probability `--p1`.
    BitPhaseFlip,
    /// Depolarizing channel; replaces the qubit with the maximally mixed state with probability `--p1`.
    Depolarizing,
    /// Amplitude-damping channel; models energy dissipation (T₁ relaxation) with parameter `--p1`.
    AmplitudeDamping,
    /// Phase-damping channel; models pure dephasing (T₂ decay) with parameter `--p1`.
    PhaseDamping,
    /// Combined amplitude- and phase-damping channel (T₁ + T₂); requires both `--p1` and `--q1`.
    AmplitudePhaseDamping,
}

impl ChannelKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelKind::Identity => "identity",
            ChannelKind::BitFlip => "bit-flip",
            ChannelKind::PhaseFlip => "phase-flip",
            ChannelKind::BitPhaseFlip => "bit-phase-flip",
            ChannelKind::Depolarizing => "depolarizing",
            ChannelKind::AmplitudeDamping => "amplitude-damping",
            ChannelKind::PhaseDamping => "phase-damping",
            ChannelKind::AmplitudePhaseDamping => "amplitude-phase-damping",
        }
    }
}
// ── Channel mix (JSON-based multi-channel) ────────────────────────────────────

/// One entry in a channel-config JSON file.
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelSpec {
    /// Channel type name: "identity", "bit-flip", "phase-flip", "bit-phase-flip",
    /// "depolarizing", "amplitude-damping", "phase-damping",
    /// "amplitude-phase-damping".
    #[serde(rename = "type")]
    pub kind: String,
    /// Fixed primary noise probability p ∈ [0, 1]. Ignored when `p_range` is set.
    #[serde(default)]
    pub p: f64,
    /// Fixed second noise parameter q ∈ [0, 1]. Ignored when `q_range` is set.
    #[serde(default)]
    pub q: f64,
    /// Per-shot uniform range for p: `[min, max]`. Overrides `p` when present.
    /// Each shot samples a fresh value uniformly from [min, max].
    #[serde(default, alias = "p1_range")]
    pub p_range: Option<[f64; 2]>,
    /// Minimum p for uniform sampling.
    #[serde(default, alias = "p_min", alias = "p1_min")]
    pub p1_min: Option<f64>,
    /// Maximum p for uniform sampling.
    #[serde(default, alias = "p_max", alias = "p1_max")]
    pub p1_max: Option<f64>,

    /// Per-shot uniform range for q: `[min, max]`. Overrides `q` when present.
    /// Each shot samples a fresh value uniformly from [min, max].
    #[serde(default, alias = "q1_range")]
    pub q_range: Option<[f64; 2]>,
    /// Minimum q for uniform sampling.
    #[serde(default, alias = "q_min", alias = "q1_min")]
    pub q1_min: Option<f64>,
    /// Maximum q for uniform sampling.
    #[serde(default, alias = "q_max", alias = "q1_max")]
    pub q1_max: Option<f64>,
    /// Relative weight for random selection (need not sum to 1).
    #[serde(default = "default_weight")]
    pub weight: f64,
}

fn default_weight() -> f64 {
    1.0
}

pub type ChannelMix = Vec<ChannelSpec>;

/// Load a channel mix from a JSON file.
pub fn load_channel_mix(path: &str) -> Result<ChannelMix, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read channel config '{path}': {e}"))?;
    let mix: ChannelMix = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid channel config '{path}': {e}"))?;
    if mix.is_empty() {
        return Err(format!(
            "Channel config '{path}' must have at least one entry"
        ));
    }
    Ok(mix)
}

/// Build a single-entry mix from the CLI flags.
pub fn single_channel_mix(kind: &ChannelKind, p: Option<f64>, q: Option<f64>) -> ChannelMix {
    let needs_p = !matches!(kind, ChannelKind::Identity);
    let needs_q = matches!(kind, ChannelKind::AmplitudePhaseDamping);

    let p_val = if needs_p {
        p.unwrap_or_else(|| {
            eprintln!("Error: --p1 is required for channel '{}'", kind.as_str());
            std::process::exit(1);
        })
    } else {
        p.unwrap_or(0.0)
    };

    let q_val = if needs_q {
        q.unwrap_or_else(|| {
            eprintln!("Error: --q1 is required for channel 'amplitude-phase-damping'");
            std::process::exit(1);
        })
    } else {
        0.0
    };

    vec![ChannelSpec {
        kind: kind.as_str().to_string(),
        p: p_val,
        q: q_val,
        p_range: None,
        p1_min: None,
        p1_max: None,
        q_range: None,
        q1_min: None,
        q1_max: None,
        weight: 1.0,
    }]
}

// ── Channel info (what gets stored in RunData) ────────────────────────────────

/// Metadata about the channel actually used in a shot — written to CSV/JSON.
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub type_name: String,
    pub p: f64,
    pub q: f64,
}

// ── Sampling ──────────────────────────────────────────────────────────────────

/// Draw one channel from the mix using the current thread-local RNG.
///
/// For a single-entry mix with no ranges the RNG is NOT consumed, preserving
/// full backward compatibility with `--seed` reproducibility.
/// When `p_range` or `q_range` is set on the selected entry, one RNG call per
/// range is made after channel selection to sample a uniform value.
pub fn sample_channel(mix: &ChannelMix) -> (QuantumChannel, ChannelInfo) {
    let spec = if mix.len() == 1 {
        &mix[0]
    } else {
        let total: f64 = mix.iter().map(|s| s.weight).sum();
        let roll = qcrypto::rng::random_f64() * total;
        let mut cum = 0.0;
        let mut chosen = mix.last().unwrap();
        for s in mix {
            cum += s.weight;
            if roll < cum {
                chosen = s;
                break;
            }
        }
        chosen
    };

    let p = if let Some([lo, hi]) = spec.p_range {
        lo + qcrypto::rng::random_f64() * (hi - lo)
    } else if let (Some(lo), Some(hi)) = (spec.p1_min, spec.p1_max) {
        lo + qcrypto::rng::random_f64() * (hi - lo)
    } else {
        spec.p
    };

    let q = if let Some([lo, hi]) = spec.q_range {
        lo + qcrypto::rng::random_f64() * (hi - lo)
    } else if let (Some(lo), Some(hi)) = (spec.q1_min, spec.q1_max) {
        lo + qcrypto::rng::random_f64() * (hi - lo)
    } else {
        spec.q
    };

    (
        build_by_name(&spec.kind, p, q),
        ChannelInfo {
            type_name: spec.kind.clone(),
            p,
            q,
        },
    )
}

// ── Internal builder ──────────────────────────────────────────────────────────

pub(crate) fn build_by_name(kind: &str, p: f64, q: f64) -> QuantumChannel {
    match kind {
        "identity" => QuantumChannel::identity(),
        "bit-flip" => QuantumChannel::bit_flip(p),
        "phase-flip" => QuantumChannel::phase_flip(p),
        "bit-phase-flip" => QuantumChannel::bit_phase_flip(p),
        "depolarizing" => QuantumChannel::depolarizing(p),
        "amplitude-damping" => QuantumChannel::amplitude_damping(p),
        "phase-damping" => QuantumChannel::phase_damping(p),
        "amplitude-phase-damping" => QuantumChannel::combined_amplitude_phase_damping(p, q),
        other => {
            eprintln!("Unknown channel type '{other}', defaulting to bit-flip(0)");
            QuantumChannel::bit_flip(0.0)
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ── ChannelKind::as_str covers all variants ───────────────────────────────

    #[test]
    fn as_str_all_variants() {
        use ChannelKind::*;
        assert_eq!(Identity.as_str(), "identity");
        assert_eq!(BitFlip.as_str(), "bit-flip");
        assert_eq!(PhaseFlip.as_str(), "phase-flip");
        assert_eq!(BitPhaseFlip.as_str(), "bit-phase-flip");
        assert_eq!(Depolarizing.as_str(), "depolarizing");
        assert_eq!(AmplitudeDamping.as_str(), "amplitude-damping");
        assert_eq!(PhaseDamping.as_str(), "phase-damping");
        assert_eq!(AmplitudePhaseDamping.as_str(), "amplitude-phase-damping");
    }

    // ── single_channel_mix ────────────────────────────────────────────────────

    #[test]
    fn single_mix_structure() {
        let mix = single_channel_mix(&ChannelKind::Depolarizing, Some(0.05), None);
        assert_eq!(mix.len(), 1);
        assert_eq!(mix[0].kind, "depolarizing");
        assert!((mix[0].p - 0.05).abs() < 1e-12);
        assert!((mix[0].q - 0.0).abs() < 1e-12);
        assert!((mix[0].weight - 1.0).abs() < 1e-12);
    }

    #[test]
    fn single_mix_amplitude_phase_damping() {
        let mix = single_channel_mix(&ChannelKind::AmplitudePhaseDamping, Some(0.1), Some(0.2));
        assert_eq!(mix[0].kind, "amplitude-phase-damping");
        assert!((mix[0].p - 0.1).abs() < 1e-12);
        assert!((mix[0].q - 0.2).abs() < 1e-12);
    }

    // ── load_channel_mix ──────────────────────────────────────────────────────

    fn write_temp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "{content}").unwrap();
        f
    }

    #[test]
    fn load_valid_mix() {
        let f = write_temp(
            r#"[
            {"type":"bit-flip","p":0.01,"weight":2.0},
            {"type":"depolarizing","p":0.05}
        ]"#,
        );
        let mix = load_channel_mix(f.path().to_str().unwrap()).unwrap();
        assert_eq!(mix.len(), 2);
        assert_eq!(mix[0].kind, "bit-flip");
        assert!((mix[0].p - 0.01).abs() < 1e-12);
        assert!((mix[0].weight - 2.0).abs() < 1e-12);
        assert_eq!(mix[1].kind, "depolarizing");
        // weight defaults to 1.0 when omitted
        assert!((mix[1].weight - 1.0).abs() < 1e-12);
        // q defaults to 0.0 when omitted
        assert!((mix[1].q - 0.0).abs() < 1e-12);
    }

    #[test]
    fn load_amplitude_phase_damping_with_q() {
        let f = write_temp(r#"[{"type":"amplitude-phase-damping","p":0.04,"q":0.02}]"#);
        let mix = load_channel_mix(f.path().to_str().unwrap()).unwrap();
        assert!((mix[0].p - 0.04).abs() < 1e-12);
        assert!((mix[0].q - 0.02).abs() < 1e-12);
    }

    #[test]
    fn load_invalid_json() {
        let f = write_temp("not json at all");
        assert!(load_channel_mix(f.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn load_empty_array() {
        let f = write_temp("[]");
        let err = load_channel_mix(f.path().to_str().unwrap()).unwrap_err();
        assert!(err.contains("at least one entry"));
    }

    #[test]
    fn load_missing_file() {
        let err = load_channel_mix("/nonexistent/path/channel.json").unwrap_err();
        assert!(err.contains("Cannot read"));
    }

    // ── sample_channel ────────────────────────────────────────────────────────

    #[test]
    fn sample_single_entry_returns_correct_info() {
        let mix = single_channel_mix(&ChannelKind::PhaseFlip, Some(0.03), None);
        let (_, info) = sample_channel(&mix);
        assert_eq!(info.type_name, "phase-flip");
        assert!((info.p - 0.03).abs() < 1e-12);
    }

    #[test]
    fn sample_multi_entry_selects_by_weight() {
        // Weight 1000 vs 0 — should always pick bit-flip.
        // Tiny nonzero weight for depolarizing so totals are correct.
        let mix = vec![
            ChannelSpec {
                kind: "bit-flip".into(),
                p: 0.01,
                q: 0.0,
                p_range: None,
                p1_min: None,
                p1_max: None,
                q_range: None,
                q1_min: None,
                q1_max: None,
                weight: 1_000_000.0,
            },
            ChannelSpec {
                kind: "depolarizing".into(),
                p: 0.05,
                q: 0.0,
                p_range: None,
                p1_min: None,
                p1_max: None,
                q_range: None,
                q1_min: None,
                q1_max: None,
                weight: 0.000001,
            },
        ];
        qcrypto::rng::set_global_seed(42);
        for _ in 0..20 {
            let (_, info) = sample_channel(&mix);
            assert_eq!(info.type_name, "bit-flip");
        }
    }

    #[test]
    fn sample_multi_entry_selects_by_weight_second() {
        let mix = vec![
            ChannelSpec {
                kind: "bit-flip".into(),
                p: 0.01,
                q: 0.0,
                p_range: None,
                p1_min: None,
                p1_max: None,
                q_range: None,
                q1_min: None,
                q1_max: None,
                weight: 0.0,
            },
            ChannelSpec {
                kind: "depolarizing".into(),
                p: 0.05,
                q: 0.0,
                p_range: None,
                p1_min: None,
                p1_max: None,
                q_range: None,
                q1_min: None,
                q1_max: None,
                weight: 1.0,
            },
        ];
        qcrypto::rng::set_global_seed(42);
        let (_, info) = sample_channel(&mix);
        assert_eq!(info.type_name, "depolarizing");
    }

    #[test]
    fn sample_info_matches_spec() {
        let mix = vec![ChannelSpec {
            kind: "amplitude-phase-damping".into(),
            p: 0.07,
            q: 0.03,
            p_range: None,
            p1_min: None,
            p1_max: None,
            q_range: None,
            q1_min: None,
            q1_max: None,
            weight: 1.0,
        }];
        let (_, info) = sample_channel(&mix);
        assert_eq!(info.type_name, "amplitude-phase-damping");
        assert!((info.p - 0.07).abs() < 1e-12);
        assert!((info.q - 0.03).abs() < 1e-12);
    }

    // ── build_by_name (all types smoke test) ──────────────────────────────────

    #[test]
    fn build_all_channel_types() {
        for kind in [
            "bit-flip",
            "phase-flip",
            "bit-phase-flip",
            "depolarizing",
            "amplitude-damping",
            "phase-damping",
            "amplitude-phase-damping",
        ] {
            // Should not panic
            let _ = build_by_name(kind, 0.0, 0.0);
        }
    }

    #[test]
    fn build_unknown_type_does_not_panic() {
        let _ = build_by_name("totally-unknown", 0.0, 0.0);
    }

    #[test]
    fn test_sample_with_ranges() {
        let mix = vec![ChannelSpec {
            kind: "amplitude-phase-damping".into(),
            p: 0.0,
            q: 0.0,
            p_range: Some([0.1, 0.2]),
            p1_min: None,
            p1_max: None,
            q_range: Some([0.01, 0.05]),
            q1_min: None,
            q1_max: None,
            weight: 1.0,
        }];
        let (_, info) = sample_channel(&mix);
        assert!(info.p >= 0.1 && info.p <= 0.2);
        assert!(info.q >= 0.01 && info.q <= 0.05);

        // Test with p1_min/max
        let mix2 = vec![ChannelSpec {
            kind: "bit-flip".into(),
            p: 0.0,
            q: 0.0,
            p_range: None,
            p1_min: Some(0.3),
            p1_max: Some(0.4),
            q_range: None,
            q1_min: Some(0.02),
            q1_max: Some(0.04),
            weight: 1.0,
        }];
        let (_, info2) = sample_channel(&mix2);
        assert!(info2.p >= 0.3 && info2.p <= 0.4);
        assert!(info2.q >= 0.02 && info2.q <= 0.04);
    }
}
