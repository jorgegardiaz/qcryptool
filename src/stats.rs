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

pub enum Aggregate {
    Qkd(QkdAgg),
    Auth(AuthAgg),
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
    }
    s
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
}
