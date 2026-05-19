use crate::run::RunData;

// ── Basic statistics ──────────────────────────────────────────────────────────

pub fn pct(n: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        100.0 * n as f64 / total as f64
    }
}

pub fn mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        0.0
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

pub fn std_dev(v: &[f64]) -> f64 {
    if v.len() < 2 {
        return 0.0;
    }
    let m = mean(v);
    (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64).sqrt()
}

// ── Aggregate types ───────────────────────────────────────────────────────────

pub struct QkdAgg {
    pub protocol: &'static str,
    pub shots: usize,
    pub mean_qber: f64,
    pub std_qber: f64,
    pub mean_key: f64,
    pub std_key: f64,
    pub match_count: usize,
    /// (mean, std, bell_violations) — only present for E91
    pub chsh: Option<(f64, f64, usize)>,
}

pub struct AuthAgg {
    pub shots: usize,
    pub mean_accuracy: f64,
    pub std_accuracy: f64,
    pub auth_count: usize,
}

pub struct QdsAgg {
    pub shots: usize,
    pub mean_bob_mismatch_rate: f64,
    pub std_bob_mismatch_rate: f64,
    pub mean_charlie_mismatch_rate: f64,
    pub std_charlie_mismatch_rate: f64,
    pub accept_count: usize,
    pub mean_eve_count: f64,
}

pub enum Aggregate {
    Qkd(QkdAgg),
    Auth(AuthAgg),
    Qds(QdsAgg),
}

// ── Computation ───────────────────────────────────────────────────────────────

pub fn compute(runs: &[RunData]) -> Aggregate {
    match &runs[0] {
        RunData::Qkd(first) => {
            let qbers: Vec<f64> = runs
                .iter()
                .filter_map(|r| {
                    let RunData::Qkd(d) = r else { return None };
                    d.qber_available.then_some(d.qber)
                })
                .collect();
            let keys: Vec<f64> = runs
                .iter()
                .filter_map(|r| {
                    let RunData::Qkd(d) = r else { return None };
                    Some(d.key_length as f64)
                })
                .collect();
            let match_count = runs
                .iter()
                .filter(|r| matches!(r, RunData::Qkd(d) if d.keys_match))
                .count();
            let chsh_vals: Vec<f64> = runs
                .iter()
                .filter_map(|r| {
                    let RunData::Qkd(d) = r else { return None };
                    d.chsh_value
                })
                .collect();
            let chsh = if chsh_vals.is_empty() {
                None
            } else {
                let violations = chsh_vals.iter().filter(|&&v| v.abs() > 2.0).count();
                Some((mean(&chsh_vals), std_dev(&chsh_vals), violations))
            };
            Aggregate::Qkd(QkdAgg {
                protocol: first.protocol,
                shots: runs.len(),
                mean_qber: mean(&qbers),
                std_qber: std_dev(&qbers),
                mean_key: mean(&keys),
                std_key: std_dev(&keys),
                match_count,
                chsh,
            })
        }
        RunData::Auth(_) => {
            let accs: Vec<f64> = runs
                .iter()
                .filter_map(|r| {
                    let RunData::Auth(d) = r else { return None };
                    Some(d.accuracy)
                })
                .collect();
            let auth_count = runs
                .iter()
                .filter(|r| matches!(r, RunData::Auth(d) if d.authenticated))
                .count();
            Aggregate::Auth(AuthAgg {
                shots: runs.len(),
                mean_accuracy: mean(&accs),
                std_accuracy: std_dev(&accs),
                auth_count,
            })
        }
        RunData::Qds(_) => {
            let bob_rates: Vec<f64> = runs
                .iter()
                .filter_map(|r| {
                    let RunData::Qds(d) = r else { return None };
                    Some(d.bob_mismatch_rate)
                })
                .collect();
            let charlie_rates: Vec<f64> = runs
                .iter()
                .filter_map(|r| {
                    let RunData::Qds(d) = r else { return None };
                    Some(d.charlie_mismatch_rate)
                })
                .collect();
            let accept_count = runs
                .iter()
                .filter(|r| matches!(r, RunData::Qds(d) if d.signature_accepted))
                .count();
            let eve_counts: Vec<f64> = runs
                .iter()
                .filter_map(|r| {
                    let RunData::Qds(d) = r else { return None };
                    Some(d.eve_intercepted_count as f64)
                })
                .collect();
            Aggregate::Qds(QdsAgg {
                shots: runs.len(),
                mean_bob_mismatch_rate: mean(&bob_rates),
                std_bob_mismatch_rate: std_dev(&bob_rates),
                mean_charlie_mismatch_rate: mean(&charlie_rates),
                std_charlie_mismatch_rate: std_dev(&charlie_rates),
                accept_count,
                mean_eve_count: mean(&eve_counts),
            })
        }
    }
}

// ── Text formatting ───────────────────────────────────────────────────────────

pub fn fmt(agg: &Aggregate) -> String {
    let mut s = String::new();
    match agg {
        Aggregate::Qkd(a) => {
            s.push_str(&format!(
                "\n═══════════════ Aggregate ({} shots) ═══════════════\n",
                a.shots
            ));
            s.push_str(&format!("Protocol       : {}\n", a.protocol));
            s.push_str(&format!(
                "QBER           : {:.4} ± {:.4}\n",
                a.mean_qber, a.std_qber
            ));
            s.push_str(&format!(
                "Key length     : {:.1} ± {:.1} bits\n",
                a.mean_key, a.std_key
            ));
            s.push_str(&format!(
                "Keys match     : {}/{} ({:.1}%)\n",
                a.match_count,
                a.shots,
                pct(a.match_count, a.shots)
            ));
            if let Some((mc, sc, viol)) = a.chsh {
                s.push_str(&format!("CHSH S-value   : {:.4} ± {:.4}\n", mc, sc));
                s.push_str(&format!(
                    "Bell violated  : {}/{} ({:.1}%)\n",
                    viol,
                    a.shots,
                    pct(viol, a.shots)
                ));
            }
        }
        Aggregate::Auth(a) => {
            s.push_str(&format!(
                "\n═══════════════ Aggregate ({} shots) ═══════════════\n",
                a.shots
            ));
            s.push_str("Protocol       : QIA-QZKP\n");
            s.push_str(&format!(
                "Accuracy       : {:.4} ± {:.4}\n",
                a.mean_accuracy, a.std_accuracy
            ));
            s.push_str(&format!(
                "Auth rate      : {}/{} ({:.1}%)\n",
                a.auth_count,
                a.shots,
                pct(a.auth_count, a.shots)
            ));
        }
        Aggregate::Qds(a) => {
            s.push_str(&format!(
                "\n═══════════════ Aggregate ({} shots) ═══════════════\n",
                a.shots
            ));
            s.push_str("Protocol       : GC01 (QDS)\n");
            s.push_str(&format!(
                "Bob mismatch   : {:.4} ± {:.4}\n",
                a.mean_bob_mismatch_rate, a.std_bob_mismatch_rate
            ));
            s.push_str(&format!(
                "Charlie mism.  : {:.4} ± {:.4}\n",
                a.mean_charlie_mismatch_rate, a.std_charlie_mismatch_rate
            ));
            s.push_str(&format!(
                "Sig. accepted  : {}/{} ({:.1}%)\n",
                a.accept_count,
                a.shots,
                pct(a.accept_count, a.shots)
            ));
            s.push_str(&format!("Eve intercepts : {:.1} avg\n", a.mean_eve_count));
        }
    }
    s
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ChannelInfo;
    use crate::run::{QdsRun, QkdRun, RunData};

    #[test]
    fn pct_zero_total() {
        assert_eq!(pct(0, 0), 0.0);
    }

    #[test]
    fn pct_normal() {
        assert!((pct(1, 4) - 25.0).abs() < 1e-10);
        assert!((pct(3, 3) - 100.0).abs() < 1e-10);
    }

    #[test]
    fn mean_empty() {
        assert_eq!(mean(&[]), 0.0);
    }

    #[test]
    fn mean_single() {
        assert!((mean(&[7.0]) - 7.0).abs() < 1e-10);
    }

    #[test]
    fn mean_multiple() {
        assert!((mean(&[2.0, 4.0, 6.0]) - 4.0).abs() < 1e-10);
    }

    #[test]
    fn std_dev_empty() {
        assert_eq!(std_dev(&[]), 0.0);
    }

    #[test]
    fn std_dev_single() {
        assert_eq!(std_dev(&[5.0]), 0.0);
    }

    #[test]
    fn std_dev_uniform() {
        // All same value → std dev = 0
        assert!(std_dev(&[3.0, 3.0, 3.0]) < 1e-10);
    }

    #[test]
    fn std_dev_known() {
        // population std dev of [2, 4, 4, 4, 5, 5, 7, 9] = 2.0
        let v = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        assert!((std_dev(&v) - 2.0).abs() < 1e-10);
    }

    // ── QdsAgg compute & fmt ──────────────────────────────────────────────────

    fn make_qds(accepted: bool, bob_rate: f64, charlie_rate: f64, eve: usize) -> RunData {
        RunData::Qds(QdsRun {
            shot: 0,
            channel_bob: ChannelInfo {
                type_name: "bit-flip".into(),
                p: 0.0,
                q: 0.0,
            },
            channel_charlie: ChannelInfo {
                type_name: "bit-flip".into(),
                p: 0.0,
                q: 0.0,
            },
            num_qubits: 100,
            message: false,
            bob_mismatches: (bob_rate * 100.0) as usize,
            charlie_mismatches: (charlie_rate * 100.0) as usize,
            bob_mismatch_rate: bob_rate,
            charlie_mismatch_rate: charlie_rate,
            signature_accepted: accepted,
            eve_intercepted_count: eve,
        })
    }

    #[test]
    fn compute_qds_basic() {
        let runs = vec![make_qds(true, 0.0, 0.0, 0), make_qds(false, 0.1, 0.2, 5)];
        let agg = compute(&runs);
        let Aggregate::Qds(a) = agg else {
            panic!("expected Qds aggregate")
        };
        assert_eq!(a.shots, 2);
        assert_eq!(a.accept_count, 1);
        assert!((a.mean_bob_mismatch_rate - 0.05).abs() < 1e-10);
        assert!((a.mean_charlie_mismatch_rate - 0.1).abs() < 1e-10);
        assert!((a.mean_eve_count - 2.5).abs() < 1e-10);
    }

    #[test]
    fn fmt_qds_aggregate() {
        let runs = vec![make_qds(true, 0.0, 0.0, 0), make_qds(true, 0.01, 0.02, 1)];
        let agg = compute(&runs);
        let s = fmt(&agg);
        assert!(s.contains("GC01"));
        assert!(s.contains("Bob mismatch"));
        assert!(s.contains("Sig. accepted"));
    }

    #[test]
    fn fmt_e91_aggregate() {
        let runs = vec![
            RunData::Qkd(QkdRun {
                shot: 0,
                protocol: "E91",
                channel: ChannelInfo {
                    type_name: "id".into(),
                    p: 0.0,
                    q: 0.0,
                },
                channel_bob: None,
                raw_length: 100,
                sifted: 10,
                check_errors: 0,
                qber: 0.0,
                qber_available: true,
                chsh_value: Some(-2.8),
                eve_count: 0,
                key_length: 5,
                keys_match: true,
                alice_key_hex: None,
                bob_key_hex: None,
            }),
            RunData::Qkd(QkdRun {
                shot: 1,
                protocol: "E91",
                channel: ChannelInfo {
                    type_name: "id".into(),
                    p: 0.0,
                    q: 0.0,
                },
                channel_bob: None,
                raw_length: 100,
                sifted: 10,
                check_errors: 1,
                qber: 0.1,
                qber_available: true,
                chsh_value: Some(-1.8),
                eve_count: 0,
                key_length: 5,
                keys_match: false,
                alice_key_hex: None,
                bob_key_hex: None,
            }),
        ];
        let agg = compute(&runs);
        let s = fmt(&agg);
        assert!(s.contains("E91"));
        assert!(s.contains("CHSH S-value"));
        assert!(s.contains("Bell violated"));
    }

    #[test]
    fn compute_mixed_runs() {
        let runs = vec![
            make_qds(true, 0.0, 0.0, 0),
            RunData::Auth(crate::run::AuthRun {
                shot: 1,
                channel: ChannelInfo {
                    type_name: "id".into(),
                    p: 0.0,
                    q: 0.0,
                },
                total_qubits: 10,
                matches: 10,
                accuracy: 1.0,
                authenticated: true,
                alice_id_hex: None,
                alice_commitment_hex: None,
                bob_challenge_hex: None,
                bob_recovered_hex: None,
            }),
        ];
        let agg = compute(&runs);
        let Aggregate::Qds(a) = agg else {
            panic!("expected Qds aggregate")
        };
        assert_eq!(a.shots, 2);
    }

    #[test]
    fn compute_mixed_runs_qkd() {
        let runs = vec![
            RunData::Qkd(QkdRun {
                shot: 0,
                protocol: "BB84",
                channel: ChannelInfo {
                    type_name: "id".into(),
                    p: 0.0,
                    q: 0.0,
                },
                channel_bob: None,
                raw_length: 100,
                sifted: 10,
                check_errors: 0,
                qber: 0.0,
                qber_available: true,
                chsh_value: None,
                eve_count: 0,
                key_length: 5,
                keys_match: true,
                alice_key_hex: None,
                bob_key_hex: None,
            }),
            make_qds(true, 0.0, 0.0, 0),
        ];
        let agg = compute(&runs);
        let Aggregate::Qkd(a) = agg else {
            panic!("expected Qkd aggregate")
        };
        assert_eq!(a.shots, 2);
    }

    #[test]
    fn compute_mixed_runs_auth() {
        let runs = vec![
            RunData::Auth(crate::run::AuthRun {
                shot: 0,
                channel: ChannelInfo {
                    type_name: "id".into(),
                    p: 0.0,
                    q: 0.0,
                },
                total_qubits: 10,
                matches: 10,
                accuracy: 1.0,
                authenticated: true,
                alice_id_hex: None,
                alice_commitment_hex: None,
                bob_challenge_hex: None,
                bob_recovered_hex: None,
            }),
            make_qds(true, 0.0, 0.0, 0),
        ];
        let agg = compute(&runs);
        let Aggregate::Auth(a) = agg else {
            panic!("expected Auth aggregate")
        };
        assert_eq!(a.shots, 2);
    }

    #[test]
    fn compute_qkd_no_qber() {
        let runs = vec![RunData::Qkd(QkdRun {
            shot: 0,
            protocol: "SARG04",
            channel: ChannelInfo {
                type_name: "id".into(),
                p: 0.0,
                q: 0.0,
            },
            channel_bob: None,
            raw_length: 100,
            sifted: 10,
            check_errors: 0,
            qber: 0.0,
            qber_available: false,
            chsh_value: None,
            eve_count: 0,
            key_length: 5,
            keys_match: true,
            alice_key_hex: None,
            bob_key_hex: None,
        })];
        let agg = compute(&runs);
        let Aggregate::Qkd(a) = agg else {
            panic!("expected Qkd aggregate")
        };
        assert_eq!(a.shots, 1);
        assert_eq!(a.mean_qber, 0.0);
    }
}
