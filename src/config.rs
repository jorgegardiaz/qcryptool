use serde::Deserialize;

use crate::channel::{ChannelMix, ChannelSpec};

// ── Experiment configuration ──────────────────────────────────────────────────

/// Full experiment description loaded from a `--experiment-config` JSON file.
///
/// All fields are optional; missing fields fall back to the corresponding CLI
/// flag values (or their defaults).
#[derive(Debug, Default, Deserialize)]
pub struct ExperimentConfig {
    /// Protocol name (e.g. "bb84", "bbm92", etc.).
    pub protocol: Option<String>,
    // ── Run parameters ────────────────────────────────────────────────────────
    /// Number of qubits / pairs / rounds per shot (maps to -n).
    pub num_qubits: Option<usize>,
    /// Number of independent shots to run (maps to -s).
    pub shots: Option<usize>,
    /// RNG seed for reproducibility (maps to --seed).
    pub seed: Option<u64>,
    /// Output file path (.json / .csv / .txt) (maps to -o).
    pub out_file: Option<String>,
    /// Include raw keys / vectors in output (maps to --detail).
    pub detail: Option<bool>,
    /// Explicitly control if keys are written to output file (overrides detail for file output).
    pub keys_out: Option<bool>,

    // ── Primary channel (Alice / single-qubit / GC01 Bob) ────────────────────
    /// Channel name (e.g. "bit-flip").  Used when `channel_config` is absent.
    pub channel1: Option<String>,
    /// Fixed primary noise p1.  Used when `channel_config` is absent.
    pub p1: Option<f64>,
    /// Fixed second noise q1 (amplitude-phase-damping only).
    pub q1: Option<f64>,
    /// Primary noise range [min, max].
    pub p1_range: Option<[f64; 2]>,
    /// Primary noise minimum (alias for p1_range).
    pub p1_min: Option<f64>,
    /// Primary noise maximum (alias for p1_range).
    pub p1_max: Option<f64>,
    /// Secondary noise range [min, max].
    pub q1_range: Option<[f64; 2]>,
    /// Secondary noise minimum (alias for q1_range).
    pub q1_min: Option<f64>,
    /// Secondary noise maximum (alias for q1_range).
    pub q1_max: Option<f64>,

    /// Channel mix array (same format as `--channel-config`).
    /// When present, `channel1` / `p1` / `q1` / ranges are ignored.
    pub channel_config: Option<Vec<ChannelSpec>>,
    /// Path to a JSON file containing the channel mix.
    /// Overrides `channel_config` and individual noise parameters.
    pub channel_config_file: Option<String>,

    // ── Secondary channel (Bob for BBM92/E91, Charlie for GC01) ─────────────
    /// Second channel name.  Defaults to `channel1` when absent.
    pub channel2: Option<String>,
    /// Fixed noise p2 for the second channel.  Defaults to `p1` when absent.
    pub p2: Option<f64>,
    /// Fixed noise q2 for the second channel.  Defaults to `q1` when absent.
    pub q2: Option<f64>,
    /// Second channel noise range [min, max].
    pub p2_range: Option<[f64; 2]>,
    /// Second channel noise minimum.
    pub p2_min: Option<f64>,
    /// Second channel noise maximum.
    pub p2_max: Option<f64>,
    /// Second channel second noise range [min, max].
    pub q2_range: Option<[f64; 2]>,
    /// Second channel second noise minimum.
    pub q2_min: Option<f64>,
    /// Second channel second noise maximum.
    pub q2_max: Option<f64>,

    /// Channel mix for the second channel.
    /// When present, `channel2` / `p2` / `q2` / ranges are ignored.
    pub channel_config2: Option<Vec<ChannelSpec>>,
    /// Path to a JSON file containing the channel mix for the second channel.
    /// Overrides `channel_config2` and individual noise parameters.
    pub channel_config2_file: Option<String>,

    // ── Protocol-specific parameters ─────────────────────────────────────────
    /// Eve interception probability ∈ [0, 1] (maps to --eve-ratio).
    pub eve_ratio: Option<f64>,
    /// Fraction of sifted bits for QBER estimation (maps to --check-ratio).
    pub check_ratio: Option<f64>,
    /// Acceptance threshold (QIA-QZKP / GC01) (maps to --threshold).
    pub threshold: Option<f64>,
}

/// Load and parse an experiment config JSON file; exits on error.
pub fn load_experiment_config(path: &str) -> ExperimentConfig {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Error: cannot read experiment config '{path}': {e}");
        std::process::exit(1);
    });
    serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Error: invalid experiment config '{path}': {e}");
        std::process::exit(1);
    })
}

impl ExperimentConfig {
    /// Resolve the primary channel mix from the experiment config.
    pub fn primary_mix(&self) -> ChannelMix {
        if let Some(path) = &self.channel_config_file {
            return crate::channel::load_channel_mix(path).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
        }
        resolve_mix_from_parts(
            self.channel_config.clone(),
            self.channel1.as_deref().unwrap_or("identity"),
            self.p1,
            self.q1,
            self.p1_range,
            self.p1_min,
            self.p1_max,
            self.q1_range,
            self.q1_min,
            self.q1_max,
            "p1",
            "q1",
        )
    }

    /// Resolve the secondary channel mix.
    ///
    /// Falls back to the primary mix when neither `channel_config2`,
    /// `channel2`, `p2`, nor `q2` are present.
    pub fn secondary_mix(&self) -> ChannelMix {
        if let Some(path) = &self.channel_config2_file {
            return crate::channel::load_channel_mix(path).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
        }

        let has_secondary = self.channel_config2.is_some()
            || self.channel2.is_some()
            || self.p2.is_some()
            || self.q2.is_some()
            || self.p2_range.is_some()
            || self.p2_min.is_some()
            || self.p2_max.is_some()
            || self.q2_range.is_some()
            || self.q2_min.is_some()
            || self.q2_max.is_some();

        if has_secondary {
            let ch = self
                .channel2
                .as_deref()
                .unwrap_or(self.channel1.as_deref().unwrap_or("identity"));
            resolve_mix_from_parts(
                self.channel_config2.clone(),
                ch,
                self.p2.or(self.p1),
                self.q2.or(self.q1),
                self.p2_range.or(self.p1_range),
                self.p2_min.or(self.p1_min),
                self.p2_max.or(self.p1_max),
                self.q2_range.or(self.q1_range),
                self.q2_min.or(self.q1_min),
                self.q2_max.or(self.q1_max),
                "p2",
                "q2",
            )
        } else {
            self.primary_mix()
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────
fn resolve_mix_from_parts(
    specs: Option<Vec<ChannelSpec>>,
    channel: &str,
    p: Option<f64>,
    q: Option<f64>,
    p_range: Option<[f64; 2]>,
    p_min: Option<f64>,
    p_max: Option<f64>,
    q_range: Option<[f64; 2]>,
    q_min: Option<f64>,
    q_max: Option<f64>,
    p_arg: &str,
    q_arg: &str,
) -> ChannelMix {
    if let Some(mix) = specs {
        if mix.is_empty() {
            eprintln!("Error: channel_config must have at least one entry");
            std::process::exit(1);
        }
        return mix;
    }
    let needs_p = channel != "identity";
    let needs_q = channel == "amplitude-phase-damping";

    let has_p_range = p_range.is_some() || (p_min.is_some() && p_max.is_some());
    let p_val = if needs_p && !has_p_range {
        p.unwrap_or_else(|| {
            eprintln!("Error: '{p_arg}' (or range) is required for channel '{channel}'");
            std::process::exit(1);
        })
    } else {
        p.unwrap_or(0.0)
    };

    let has_q_range = q_range.is_some() || (q_min.is_some() && q_max.is_some());
    let q_val = if needs_q && !has_q_range {
        q.unwrap_or_else(|| {
            eprintln!(
                "Error: '{q_arg}' (or range) is required for channel 'amplitude-phase-damping'"
            );
            std::process::exit(1);
        })
    } else {
        0.0
    };

    vec![ChannelSpec {
        kind: channel.to_string(),
        p: p_val,
        q: q_val,
        p_range,
        p1_min: p_min,
        p1_max: p_max,
        q_range,
        q1_min: q_min,
        q1_max: q_max,
        weight: 1.0,
    }]
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_experiment_config_ranges() {
        let mut f = NamedTempFile::new().unwrap();
        write!(
            f,
            r#"{{
            "num_qubits": 500,
            "shots": 10,
            "p1_min": 0.01,
            "p1_max": 0.05,
            "channel1": "depolarizing"
        }}"#
        )
        .unwrap();

        let cfg = load_experiment_config(f.path().to_str().unwrap());
        assert_eq!(cfg.num_qubits, Some(500));
        assert_eq!(cfg.shots, Some(10));
        assert_eq!(cfg.p1_min, Some(0.01));
        assert_eq!(cfg.p1_max, Some(0.05));

        let mix = cfg.primary_mix();
        assert_eq!(mix.len(), 1);
        assert_eq!(mix[0].kind, "depolarizing");
        assert_eq!(mix[0].p1_min, Some(0.01));
        assert_eq!(mix[0].p1_max, Some(0.05));
    }

    #[test]
    fn test_experiment_config_with_array() {
        let mut f = NamedTempFile::new().unwrap();
        write!(
            f,
            r#"{{
            "shots": 5,
            "channel_config": [
                {{ "type": "bit-flip", "p_range": [0.0, 0.1] }},
                {{ "type": "phase-flip", "p_min": 0.02, "p_max": 0.04 }}
            ]
        }}"#
        )
        .unwrap();

        let cfg = load_experiment_config(f.path().to_str().unwrap());
        let mix = cfg.primary_mix();
        assert_eq!(mix.len(), 2);
        assert_eq!(mix[0].kind, "bit-flip");
        assert_eq!(mix[0].p_range, Some([0.0, 0.1]));
        assert_eq!(mix[1].kind, "phase-flip");
        assert_eq!(mix[1].p1_min, Some(0.02));
        assert_eq!(mix[1].p1_max, Some(0.04));
    }

    #[test]
    fn test_secondary_mix_fallback() {
        let cfg = ExperimentConfig {
            protocol: None,
            num_qubits: None,
            shots: None,
            seed: None,
            out_file: None,
            detail: None,
            keys_out: None,
            channel1: Some("bit-flip".into()),
            p1: Some(0.01),
            q1: None,
            p1_range: None,
            p1_min: None,
            p1_max: None,
            q1_range: None,
            q1_min: None,
            q1_max: None,
            channel_config: None,
            channel_config_file: None,
            channel2: None,
            p2: None,
            q2: None,
            p2_range: None,
            p2_min: None,
            p2_max: None,
            q2_range: None,
            q2_min: None,
            q2_max: None,
            channel_config2: None,
            channel_config2_file: None,
            eve_ratio: None,
            check_ratio: None,
            threshold: None,
        };
        let m1 = cfg.primary_mix();
        let m2 = cfg.secondary_mix();
        assert_eq!(m1[0].kind, m2[0].kind);
        assert_eq!(m1[0].p, m2[0].p);
    }

    #[test]
    fn test_secondary_mix_explicit() {
        let mut cfg = ExperimentConfig {
            protocol: None,
            num_qubits: None,
            shots: None,
            seed: None,
            out_file: None,
            detail: None,
            keys_out: None,
            channel1: Some("bit-flip".into()),
            p1: Some(0.01),
            q1: None,
            p1_range: None,
            p1_min: None,
            p1_max: None,
            q1_range: None,
            q1_min: None,
            q1_max: None,
            channel_config: None,
            channel_config_file: None,
            channel2: Some("depolarizing".into()),
            p2: Some(0.05),
            q2: None,
            p2_range: None,
            p2_min: None,
            p2_max: None,
            q2_range: None,
            q2_min: None,
            q2_max: None,
            channel_config2: None,
            channel_config2_file: None,
            eve_ratio: None,
            check_ratio: None,
            threshold: None,
        };
        let m2 = cfg.secondary_mix();
        assert_eq!(m2[0].kind, "depolarizing");
        assert_eq!(m2[0].p, 0.05);

        // Test with ranges
        cfg.p2 = None;
        cfg.p2_min = Some(0.01);
        cfg.p2_max = Some(0.03);
        let m3 = cfg.secondary_mix();
        assert_eq!(m3[0].p1_min, Some(0.01));

        // Test with channel_config2
        cfg.channel_config2 = Some(vec![ChannelSpec {
            kind: "phase-flip".into(),
            p: 0.02,
            q: 0.0,
            p_range: None,
            p1_min: None,
            p1_max: None,
            q_range: None,
            q1_min: None,
            q1_max: None,
            weight: 1.0,
        }]);
        let m4 = cfg.secondary_mix();
        assert_eq!(m4[0].kind, "phase-flip");
    }

    #[test]
    fn test_resolve_mix_from_parts_identity() {
        let mix = resolve_mix_from_parts(
            None, "identity", None, None, None, None, None, None, None, None, "p1", "q1",
        );
        assert_eq!(mix.len(), 1);
        assert_eq!(mix[0].kind, "identity");
    }
    #[test]
    fn test_experiment_config_default() {
        let cfg = ExperimentConfig::default();
        assert!(cfg.protocol.is_none());
        assert!(cfg.channel_config.is_none());
    }
}
