use clap::ValueEnum;
use qcrypto::QuantumChannel;
use serde::Deserialize;

// ── CLI channel (legacy single-channel flags) ─────────────────────────────────

#[derive(Clone, Debug, ValueEnum)]
pub enum ChannelKind {
    /// Bit Flip channel; uses --noise (p)
    BitFlip,
    /// Phase Flip channel; uses --noise (p)
    PhaseFlip,
    /// Bit Flip + Phase Flip channel; uses --noise (p)
    BitPhaseFlip,
    /// Depolarizing channel; uses --noise (p)
    Depolarizing,
    /// Amplitude Damping channel; uses --noise (p)
    AmplitudeDamping,
    /// Phase Damping channel; uses --noise (p)
    PhaseDamping,
    /// Amplitude Damping + Phase Damping channel; uses --noise (p) --noise2 (q)
    AmplitudePhaseDamping,
}

impl ChannelKind {
    pub fn as_str(&self) -> &'static str {
        match self {
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
    /// Channel type name: "bit-flip", "phase-flip", "bit-phase-flip",
    /// "depolarizing", "amplitude-damping", "phase-damping",
    /// "amplitude-phase-damping".
    #[serde(rename = "type")]
    pub kind: String,
    /// Primary noise probability p ∈ [0, 1].
    pub p: f64,
    /// Second noise parameter p2 ∈ [0, 1] (only for amplitude-phase-damping).
    #[serde(default)]
    pub p2: f64,
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
pub fn single_channel_mix(kind: &ChannelKind, p: f64, p2: f64) -> ChannelMix {
    vec![ChannelSpec {
        kind: kind.as_str().to_string(),
        p,
        p2,
        weight: 1.0,
    }]
}

// ── Channel info (what gets stored in RunData) ────────────────────────────────

/// Metadata about the channel actually used in a shot — written to CSV/JSON.
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub type_name: String,
    pub p: f64,
    pub p2: f64,
}

impl From<&ChannelSpec> for ChannelInfo {
    fn from(s: &ChannelSpec) -> Self {
        ChannelInfo {
            type_name: s.kind.clone(),
            p: s.p,
            p2: s.p2,
        }
    }
}

// ── Sampling ──────────────────────────────────────────────────────────────────

/// Draw one channel from the mix using the current thread-local RNG.
///
/// For a single-entry mix the RNG is NOT consumed, preserving full backward
/// compatibility with `--seed` reproducibility when `--channel-config` is
/// absent (the mix is built from CLI flags and always has weight 1.0).
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
    (
        build_by_name(&spec.kind, spec.p, spec.p2),
        ChannelInfo::from(spec),
    )
}

// ── Internal builder ──────────────────────────────────────────────────────────

pub(crate) fn build_by_name(kind: &str, p: f64, p2: f64) -> QuantumChannel {
    match kind {
        "bit-flip" => QuantumChannel::bit_flip(p),
        "phase-flip" => QuantumChannel::phase_flip(p),
        "bit-phase-flip" => QuantumChannel::bit_phase_flip(p),
        "depolarizing" => QuantumChannel::depolarizing(p),
        "amplitude-damping" => QuantumChannel::amplitude_damping(p),
        "phase-damping" => QuantumChannel::phase_damping(p),
        "amplitude-phase-damping" => QuantumChannel::combined_amplitude_phase_damping(p, p2),
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
        let mix = single_channel_mix(&ChannelKind::Depolarizing, 0.05, 0.0);
        assert_eq!(mix.len(), 1);
        assert_eq!(mix[0].kind, "depolarizing");
        assert!((mix[0].p - 0.05).abs() < 1e-12);
        assert!((mix[0].p2 - 0.0).abs() < 1e-12);
        assert!((mix[0].weight - 1.0).abs() < 1e-12);
    }

    #[test]
    fn single_mix_amplitude_phase_damping() {
        let mix = single_channel_mix(&ChannelKind::AmplitudePhaseDamping, 0.1, 0.2);
        assert_eq!(mix[0].kind, "amplitude-phase-damping");
        assert!((mix[0].p - 0.1).abs() < 1e-12);
        assert!((mix[0].p2 - 0.2).abs() < 1e-12);
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
        // p2 defaults to 0.0 when omitted
        assert!((mix[1].p2 - 0.0).abs() < 1e-12);
    }

    #[test]
    fn load_amplitude_phase_damping_with_p2() {
        let f = write_temp(r#"[{"type":"amplitude-phase-damping","p":0.04,"p2":0.02}]"#);
        let mix = load_channel_mix(f.path().to_str().unwrap()).unwrap();
        assert!((mix[0].p - 0.04).abs() < 1e-12);
        assert!((mix[0].p2 - 0.02).abs() < 1e-12);
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
        let mix = single_channel_mix(&ChannelKind::PhaseFlip, 0.03, 0.0);
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
                p2: 0.0,
                weight: 1_000_000.0,
            },
            ChannelSpec {
                kind: "depolarizing".into(),
                p: 0.05,
                p2: 0.0,
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
    fn sample_info_matches_spec() {
        let mix = vec![ChannelSpec {
            kind: "amplitude-phase-damping".into(),
            p: 0.07,
            p2: 0.03,
            weight: 1.0,
        }];
        let (_, info) = sample_channel(&mix);
        assert_eq!(info.type_name, "amplitude-phase-damping");
        assert!((info.p - 0.07).abs() < 1e-12);
        assert!((info.p2 - 0.03).abs() < 1e-12);
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
}
