use serde_json::{Value, json};
use std::fs;

use crate::run::{AuthRun, QkdRun, RunData};
use crate::stats::{self, Aggregate, AuthAgg, QkdAgg};

// ── Text formatting ───────────────────────────────────────────────────────────

pub fn fmt_qkd_run(r: &QkdRun, shots: usize) -> String {
    let mut s = String::new();
    if shots > 1 {
        s.push_str(&format!(
            "── Shot {} ──────────────────────────────────\n",
            r.shot + 1
        ));
    }
    let raw_lbl = if matches!(r.protocol, "BBM92" | "E91") {
        "Raw pairs  "
    } else {
        "Raw qubits "
    };
    let sft_lbl = if matches!(r.protocol, "B92" | "SARG04") {
        "Conclusive "
    } else {
        "Sifted bits"
    };
    s.push_str(&format!("Protocol       : {}\n", r.protocol));
    s.push_str(&format!(
        "Channel        : {} (p={}",
        r.channel.type_name, r.channel.p
    ));
    if r.channel.p2 != 0.0 {
        s.push_str(&format!(", p2={}", r.channel.p2));
    }
    s.push_str(")\n");
    s.push_str(&format!("{raw_lbl}    : {}\n", r.raw_length));
    s.push_str(&format!(
        "{sft_lbl}    : {} ({:.1}%)\n",
        r.sifted,
        stats::pct(r.sifted, r.raw_length)
    ));
    s.push_str(&format!("Check errors   : {}\n", r.check_errors));
    if r.qber_available {
        s.push_str(&format!(
            "QBER           : {:.4} ({:.2}%)\n",
            r.qber,
            r.qber * 100.0
        ));
    } else {
        s.push_str("QBER           : N/A (no check bits)\n");
    }
    if let Some(chsh) = r.chsh_value {
        let verdict = if chsh.abs() > 2.0 {
            "✓ Bell violated (secure)"
        } else {
            "✗ NOT violated (insecure!)"
        };
        s.push_str(&format!("CHSH S-value   : {:.4}  {verdict}\n", chsh));
    }
    s.push_str(&format!("Eve intercepts : {}\n", r.eve_count));
    s.push_str(&format!("Key length     : {} bits\n", r.key_length));
    s.push_str(&format!(
        "Keys match     : {}\n",
        if r.keys_match {
            "yes"
        } else {
            "no (noise or Eve)"
        }
    ));
    if let Some(h) = &r.alice_key_hex {
        s.push_str(&format!("Alice key (hex): {h}\n"));
    }
    if let Some(h) = &r.bob_key_hex {
        s.push_str(&format!("Bob key (hex)  : {h}\n"));
    }
    s
}

pub fn fmt_auth_run(r: &AuthRun, shots: usize) -> String {
    let mut s = String::new();
    if shots > 1 {
        s.push_str(&format!(
            "── Shot {} ──────────────────────────────────\n",
            r.shot + 1
        ));
    }
    s.push_str("Protocol       : QIA-QZKP\n");
    s.push_str(&format!(
        "Channel        : {} (p={}",
        r.channel.type_name, r.channel.p
    ));
    if r.channel.p2 != 0.0 {
        s.push_str(&format!(", p2={}", r.channel.p2));
    }
    s.push_str(")\n");
    s.push_str(&format!("Rounds         : {}\n", r.total_qubits));
    s.push_str(&format!(
        "Matches        : {} / {}\n",
        r.matches, r.total_qubits
    ));
    s.push_str(&format!(
        "Accuracy       : {:.4} ({:.2}%)\n",
        r.accuracy,
        r.accuracy * 100.0
    ));
    s.push_str(&format!(
        "Authenticated  : {}\n",
        if r.authenticated {
            "YES"
        } else {
            "NO (rejected)"
        }
    ));
    if let Some(h) = &r.alice_id_hex {
        s.push_str(&format!("Alice id 'a'   : {h}\n"));
    }
    if let Some(h) = &r.alice_commitment_hex {
        s.push_str(&format!("Alice commit'b': {h}\n"));
    }
    if let Some(h) = &r.bob_challenge_hex {
        s.push_str(&format!("Bob challenge  : {h}\n"));
    }
    if let Some(h) = &r.bob_recovered_hex {
        s.push_str(&format!("Bob recovered  : {h}\n"));
    }
    s
}

// ── JSON conversion ───────────────────────────────────────────────────────────

pub fn run_to_json(run: &RunData) -> Value {
    match run {
        RunData::Qkd(r) => {
            let mut j = json!({
                "shot": r.shot + 1,
                "channel_type": r.channel.type_name,
                "channel_p": r.channel.p,
                "channel_p2": r.channel.p2,
                "raw_length": r.raw_length,
                "sifted": r.sifted,
                "sift_rate": stats::pct(r.sifted, r.raw_length) / 100.0,
                "check_errors": r.check_errors,
                "qber": if r.qber_available { json!(r.qber) } else { json!(null) },
                "eve_count": r.eve_count,
                "key_length": r.key_length,
                "keys_match": r.keys_match,
            });
            if let Some(chsh) = r.chsh_value {
                j["chsh_value"] = json!(chsh);
                j["bell_violated"] = json!(chsh.abs() > 2.0);
            }
            if let Some(h) = &r.alice_key_hex {
                j["alice_key_hex"] = json!(h);
            }
            if let Some(h) = &r.bob_key_hex {
                j["bob_key_hex"] = json!(h);
            }
            j
        }
        RunData::Auth(r) => {
            let mut j = json!({
                "shot": r.shot + 1,
                "channel_type": r.channel.type_name,
                "channel_p": r.channel.p,
                "channel_p2": r.channel.p2,
                "total_qubits": r.total_qubits,
                "matches": r.matches,
                "accuracy": r.accuracy,
                "authenticated": r.authenticated,
            });
            if let Some(h) = &r.alice_id_hex {
                j["alice_id_hex"] = json!(h);
            }
            if let Some(h) = &r.alice_commitment_hex {
                j["alice_commitment_hex"] = json!(h);
            }
            if let Some(h) = &r.bob_challenge_hex {
                j["bob_challenge_hex"] = json!(h);
            }
            if let Some(h) = &r.bob_recovered_hex {
                j["bob_recovered_hex"] = json!(h);
            }
            j
        }
    }
}

pub fn aggregate_to_json(agg: &Aggregate) -> Value {
    match agg {
        Aggregate::Qkd(QkdAgg {
            protocol,
            shots,
            mean_qber,
            std_qber,
            mean_key,
            std_key,
            match_count,
            chsh,
        }) => {
            let mut j = json!({
                "protocol": protocol,
                "shots": shots,
                "mean_qber": mean_qber,
                "std_qber": std_qber,
                "mean_key_length": mean_key,
                "std_key_length": std_key,
                "keys_match_rate": *match_count as f64 / *shots as f64,
            });
            if let Some((mc, sc, viol)) = chsh {
                j["mean_chsh"] = json!(mc);
                j["std_chsh"] = json!(sc);
                j["bell_violation_rate"] = json!(*viol as f64 / *shots as f64);
            }
            j
        }
        Aggregate::Auth(AuthAgg {
            shots,
            mean_accuracy,
            std_accuracy,
            auth_count,
        }) => json!({
            "protocol": "QIA-QZKP",
            "shots": shots,
            "mean_accuracy": mean_accuracy,
            "std_accuracy": std_accuracy,
            "authentication_rate": *auth_count as f64 / *shots as f64,
        }),
    }
}

// ── CSV helpers ───────────────────────────────────────────────────────────────

pub fn qkd_to_csv(runs: &[RunData], detail: bool) -> String {
    let has_chsh = runs
        .iter()
        .any(|r| matches!(r, RunData::Qkd(d) if d.chsh_value.is_some()));
    let mut hdrs = vec![
        "shot",
        "channel_type",
        "channel_p",
        "channel_p2",
        "raw_length",
        "sifted",
        "sift_rate",
        "check_errors",
        "qber",
        "eve_count",
        "key_length",
        "keys_match",
    ];
    if has_chsh {
        hdrs.extend_from_slice(&["chsh_value", "bell_violated"]);
    }
    if detail {
        hdrs.extend_from_slice(&["alice_key_hex", "bob_key_hex"]);
    }

    let mut lines = vec![hdrs.join(",")];
    for run in runs {
        if let RunData::Qkd(r) = run {
            let mut row = vec![
                (r.shot + 1).to_string(),
                r.channel.type_name.clone(),
                r.channel.p.to_string(),
                r.channel.p2.to_string(),
                r.raw_length.to_string(),
                r.sifted.to_string(),
                format!("{:.4}", stats::pct(r.sifted, r.raw_length) / 100.0),
                r.check_errors.to_string(),
                if r.qber_available {
                    format!("{:.6}", r.qber)
                } else {
                    "N/A".into()
                },
                r.eve_count.to_string(),
                r.key_length.to_string(),
                r.keys_match.to_string(),
            ];
            if has_chsh {
                match r.chsh_value {
                    Some(c) => {
                        row.push(format!("{:.6}", c));
                        row.push((c.abs() > 2.0).to_string());
                    }
                    None => {
                        row.push("N/A".into());
                        row.push("N/A".into());
                    }
                }
            }
            if detail {
                row.push(r.alice_key_hex.clone().unwrap_or_default());
                row.push(r.bob_key_hex.clone().unwrap_or_default());
            }
            lines.push(row.join(","));
        }
    }
    lines.join("\n")
}

pub fn auth_to_csv(runs: &[RunData], detail: bool) -> String {
    let mut hdrs = vec![
        "shot",
        "channel_type",
        "channel_p",
        "channel_p2",
        "total_qubits",
        "matches",
        "accuracy",
        "authenticated",
    ];
    if detail {
        hdrs.extend_from_slice(&[
            "alice_id_hex",
            "alice_commitment_hex",
            "bob_challenge_hex",
            "bob_recovered_hex",
        ]);
    }

    let mut lines = vec![hdrs.join(",")];
    for run in runs {
        if let RunData::Auth(r) = run {
            let mut row = vec![
                (r.shot + 1).to_string(),
                r.channel.type_name.clone(),
                r.channel.p.to_string(),
                r.channel.p2.to_string(),
                r.total_qubits.to_string(),
                r.matches.to_string(),
                format!("{:.6}", r.accuracy),
                r.authenticated.to_string(),
            ];
            if detail {
                row.push(r.alice_id_hex.clone().unwrap_or_default());
                row.push(r.alice_commitment_hex.clone().unwrap_or_default());
                row.push(r.bob_challenge_hex.clone().unwrap_or_default());
                row.push(r.bob_recovered_hex.clone().unwrap_or_default());
            }
            lines.push(row.join(","));
        }
    }
    lines.join("\n")
}

// ── File output ───────────────────────────────────────────────────────────────

pub fn write_file(path: &str, runs: &[RunData], detail: bool) {
    let agg = stats::compute(runs);
    let shots = runs.len();

    let content = if path.ends_with(".json") {
        let out = json!({
            "aggregate": aggregate_to_json(&agg),
            "shots": shots,
            "runs": runs.iter().map(run_to_json).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&out).unwrap()
    } else if path.ends_with(".csv") {
        match &runs[0] {
            RunData::Qkd(_) => qkd_to_csv(runs, detail),
            RunData::Auth(_) => auth_to_csv(runs, detail),
        }
    } else {
        let mut out = String::new();
        for run in runs {
            out.push_str(
                match run {
                    RunData::Qkd(r) => fmt_qkd_run(r, shots),
                    RunData::Auth(r) => fmt_auth_run(r, shots),
                }
                .as_str(),
            );
            out.push('\n');
        }
        if shots > 1 {
            out.push_str(&stats::fmt(&agg));
        }
        out
    };

    fs::write(path, content).unwrap_or_else(|e| eprintln!("Error writing {path}: {e}"));
    println!("Results saved → {path}");
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ChannelInfo;

    // Helpers return concrete types — no if-let enum extraction needed in tests.
    fn make_qkd(
        protocol: &'static str,
        chsh: Option<f64>,
        detail: bool,
        qber_avail: bool,
    ) -> QkdRun {
        QkdRun {
            protocol,
            shot: 0,
            channel: ChannelInfo {
                type_name: "bit-flip".into(),
                p: 0.01,
                p2: 0.0,
            },
            raw_length: 1000,
            sifted: 500,
            check_errors: 5,
            qber: 0.02,
            qber_available: qber_avail,
            eve_count: 0,
            key_length: 247,
            keys_match: true,
            chsh_value: chsh,
            alice_key_hex: detail.then(|| "deadbeef".into()),
            bob_key_hex: detail.then(|| "deadbeef".into()),
        }
    }

    fn make_auth(detail: bool, authenticated: bool, p2: f64) -> AuthRun {
        AuthRun {
            shot: 0,
            channel: ChannelInfo {
                type_name: "depolarizing".into(),
                p: 0.0,
                p2,
            },
            total_qubits: 100,
            matches: 98,
            accuracy: 0.98,
            authenticated,
            alice_id_hex: detail.then(|| "aabbcc".into()),
            alice_commitment_hex: detail.then(|| "ddeeff".into()),
            bob_challenge_hex: detail.then(|| "112233".into()),
            bob_recovered_hex: detail.then(|| "445566".into()),
        }
    }

    // ── fmt_qkd_run ──────────────────────────────────────────────────────────

    #[test]
    fn fmt_qkd_run_single_shot_has_protocol() {
        let r = make_qkd("BB84", None, false, true);
        let s = fmt_qkd_run(&r, 1);
        assert!(s.contains("BB84"));
        assert!(s.contains("bit-flip"));
        assert!(!s.contains("── Shot"));
    }

    #[test]
    fn fmt_qkd_run_multi_shot_has_header() {
        let r = make_qkd("BB84", None, false, true);
        let s = fmt_qkd_run(&r, 5);
        assert!(s.contains("── Shot 1"));
    }

    #[test]
    fn fmt_qkd_run_with_chsh() {
        let r = make_qkd("E91", Some(-2.8), false, true);
        let s = fmt_qkd_run(&r, 1);
        assert!(s.contains("CHSH"));
        assert!(s.contains("Bell violated"));
    }

    #[test]
    fn fmt_qkd_run_chsh_not_violated() {
        let r = make_qkd("E91", Some(1.5), false, true);
        let s = fmt_qkd_run(&r, 1);
        assert!(s.contains("NOT violated"));
    }

    #[test]
    fn fmt_qkd_run_with_keys() {
        let r = make_qkd("BB84", None, true, true);
        let s = fmt_qkd_run(&r, 1);
        assert!(s.contains("Alice key"));
        assert!(s.contains("deadbeef"));
    }

    #[test]
    fn fmt_qkd_run_qber_unavailable() {
        let r = make_qkd("E91", None, false, false);
        let s = fmt_qkd_run(&r, 1);
        assert!(s.contains("N/A"));
    }

    // ── fmt_auth_run ──────────────────────────────────────────────────────────

    #[test]
    fn fmt_auth_run_single_shot() {
        let r = make_auth(false, true, 0.0);
        let s = fmt_auth_run(&r, 1);
        assert!(s.contains("QIA-QZKP"));
        assert!(s.contains("depolarizing"));
        assert!(!s.contains("── Shot"));
    }

    #[test]
    fn fmt_auth_run_multi_shot_has_header() {
        let r = make_auth(false, true, 0.0);
        let s = fmt_auth_run(&r, 3);
        assert!(s.contains("── Shot 1"));
    }

    #[test]
    fn fmt_auth_run_not_authenticated() {
        let r = make_auth(false, false, 0.0);
        let s = fmt_auth_run(&r, 1);
        assert!(s.contains("NO (rejected)"));
    }

    #[test]
    fn fmt_auth_run_with_p2() {
        let r = make_auth(false, true, 0.05);
        let s = fmt_auth_run(&r, 1);
        assert!(s.contains("p2=0.05"));
    }

    #[test]
    fn fmt_auth_run_with_detail() {
        let r = make_auth(true, true, 0.0);
        let s = fmt_auth_run(&r, 1);
        assert!(s.contains("aabbcc"));
        assert!(s.contains("ddeeff"));
        assert!(s.contains("112233"));
        assert!(s.contains("445566"));
    }

    // ── run_to_json ───────────────────────────────────────────────────────────

    #[test]
    fn run_to_json_qkd_has_channel_fields() {
        let j = run_to_json(&RunData::Qkd(make_qkd("BB84", None, false, true)));
        assert_eq!(j["channel_type"], "bit-flip");
        assert!((j["channel_p"].as_f64().unwrap() - 0.01).abs() < 1e-12);
    }

    #[test]
    fn run_to_json_qkd_with_chsh() {
        let j = run_to_json(&RunData::Qkd(make_qkd("E91", Some(-2.8), false, true)));
        assert!(j["chsh_value"].is_number());
        assert!(j["bell_violated"].is_boolean());
    }

    #[test]
    fn run_to_json_qkd_with_keys() {
        let j = run_to_json(&RunData::Qkd(make_qkd("BB84", None, true, true)));
        assert_eq!(j["alice_key_hex"], "deadbeef");
        assert_eq!(j["bob_key_hex"], "deadbeef");
    }

    #[test]
    fn run_to_json_qkd_qber_unavailable() {
        let j = run_to_json(&RunData::Qkd(make_qkd("E91", None, false, false)));
        assert!(j["qber"].is_null(), "qber should be null when unavailable");
    }

    #[test]
    fn run_to_json_auth() {
        let j = run_to_json(&RunData::Auth(make_auth(false, true, 0.0)));
        assert_eq!(j["channel_type"], "depolarizing");
        assert!(j["accuracy"].is_number());
        assert!(j["authenticated"].is_boolean());
    }

    #[test]
    fn run_to_json_auth_with_detail() {
        let j = run_to_json(&RunData::Auth(make_auth(true, true, 0.0)));
        assert_eq!(j["alice_id_hex"], "aabbcc");
        assert_eq!(j["bob_challenge_hex"], "112233");
    }

    // ── aggregate_to_json ─────────────────────────────────────────────────────

    #[test]
    fn aggregate_to_json_qkd() {
        let runs = vec![
            RunData::Qkd(make_qkd("BB84", None, false, true)),
            RunData::Qkd(make_qkd("BB84", None, false, true)),
        ];
        let j = aggregate_to_json(&stats::compute(&runs));
        assert_eq!(j["protocol"], "BB84");
        assert!(j["mean_qber"].is_number());
    }

    #[test]
    fn aggregate_to_json_qkd_with_chsh() {
        let runs = vec![
            RunData::Qkd(make_qkd("E91", Some(-2.8), false, true)),
            RunData::Qkd(make_qkd("E91", Some(-2.9), false, true)),
        ];
        let j = aggregate_to_json(&stats::compute(&runs));
        assert!(j["mean_chsh"].is_number());
        assert!(j["bell_violation_rate"].is_number());
    }

    #[test]
    fn aggregate_to_json_auth() {
        let runs = vec![
            RunData::Auth(make_auth(false, true, 0.0)),
            RunData::Auth(make_auth(false, true, 0.0)),
        ];
        let j = aggregate_to_json(&stats::compute(&runs));
        assert_eq!(j["protocol"], "QIA-QZKP");
        assert!(j["mean_accuracy"].is_number());
        assert!(j["authentication_rate"].is_number());
    }

    // ── CSV helpers ───────────────────────────────────────────────────────────

    #[test]
    fn qkd_csv_with_chsh_columns() {
        let runs = vec![RunData::Qkd(make_qkd("E91", Some(-2.8), false, true))];
        let csv = qkd_to_csv(&runs, false);
        assert!(csv.contains("chsh_value"), "missing chsh_value header");
        assert!(
            csv.contains("bell_violated"),
            "missing bell_violated header"
        );
    }

    #[test]
    fn qkd_csv_chsh_none_row_when_has_chsh() {
        // has_chsh=true because first run has chsh, second doesn't → second row gets "N/A"
        let runs = vec![
            RunData::Qkd(make_qkd("E91", Some(-2.8), false, true)),
            RunData::Qkd(make_qkd("E91", None, false, true)),
        ];
        let csv = qkd_to_csv(&runs, false);
        assert!(
            csv.contains("N/A"),
            "missing N/A for run with no chsh when has_chsh=true"
        );
    }

    #[test]
    fn qkd_csv_qber_na_when_unavailable() {
        let runs = vec![RunData::Qkd(make_qkd("E91", None, false, false))];
        let csv = qkd_to_csv(&runs, false);
        assert!(csv.contains("N/A"), "qber should be N/A when unavailable");
    }

    #[test]
    fn qkd_csv_skips_auth_entries_in_mixed_slice() {
        // Passing a mixed slice: Qkd rows are written, Auth rows silently skipped.
        // This exercises the closing `}` of the if-let loop (the non-matching path).
        let runs = vec![
            RunData::Qkd(make_qkd("BB84", None, false, true)),
            RunData::Auth(make_auth(false, true, 0.0)),
        ];
        let csv = qkd_to_csv(&runs, false);
        // Only one data row (the Qkd one)
        assert_eq!(csv.lines().count(), 2, "should have header + 1 data row");
    }

    #[test]
    fn auth_csv_basic_structure() {
        let runs = vec![RunData::Auth(make_auth(false, true, 0.0))];
        let csv = auth_to_csv(&runs, false);
        let hdr = csv.lines().next().unwrap();
        assert!(hdr.contains("accuracy"));
        assert!(hdr.contains("authenticated"));
        assert!(hdr.contains("channel_type"));
        assert_eq!(csv.lines().count(), 2);
    }

    #[test]
    fn auth_csv_skips_qkd_entries_in_mixed_slice() {
        // Exercises the closing `}` of the if-let loop in auth_to_csv.
        let runs = vec![
            RunData::Auth(make_auth(false, true, 0.0)),
            RunData::Qkd(make_qkd("BB84", None, false, true)),
        ];
        let csv = auth_to_csv(&runs, false);
        assert_eq!(csv.lines().count(), 2, "should have header + 1 data row");
    }

    #[test]
    fn auth_csv_with_detail() {
        let runs = vec![RunData::Auth(make_auth(true, true, 0.0))];
        let csv = auth_to_csv(&runs, true);
        let hdr = csv.lines().next().unwrap();
        assert!(hdr.contains("alice_id_hex"));
        assert!(hdr.contains("bob_recovered_hex"));
        let row = csv.lines().nth(1).unwrap();
        assert!(row.contains("aabbcc"));
    }

    // ── write_file ────────────────────────────────────────────────────────────

    #[test]
    fn write_file_csv_qkd() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("out.csv").to_str().unwrap().to_string();
        let runs = vec![RunData::Qkd(make_qkd("BB84", None, false, true))];
        write_file(&path, &runs, false);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("channel_type"));
    }

    #[test]
    fn write_file_csv_auth() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("out.csv").to_str().unwrap().to_string();
        let runs = vec![RunData::Auth(make_auth(false, true, 0.0))];
        write_file(&path, &runs, false);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("authenticated"));
    }

    #[test]
    fn write_file_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("out.json").to_str().unwrap().to_string();
        let runs = vec![RunData::Qkd(make_qkd("BB84", None, false, true))];
        write_file(&path, &runs, false);
        let content = std::fs::read_to_string(&path).unwrap();
        let j: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(j["aggregate"].is_object());
    }

    #[test]
    fn write_file_txt_qkd() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("out.txt").to_str().unwrap().to_string();
        let runs = vec![
            RunData::Qkd(make_qkd("BB84", None, false, true)),
            RunData::Qkd(make_qkd("BB84", None, false, true)),
        ];
        write_file(&path, &runs, false);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Protocol"));
        assert!(content.contains("Aggregate"));
    }

    #[test]
    fn write_file_error_is_handled_gracefully() {
        // Writing to an impossible path triggers the error handler without panicking.
        let runs = vec![RunData::Qkd(make_qkd("BB84", None, false, true))];
        write_file("/dev/null/impossible/path.csv", &runs, false);
        // Reaching here means no panic — error was handled by the closure.
    }

    #[test]
    fn write_file_txt_auth() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("out.txt").to_str().unwrap().to_string();
        let runs = vec![
            RunData::Auth(make_auth(false, true, 0.0)),
            RunData::Auth(make_auth(false, true, 0.0)),
        ];
        write_file(&path, &runs, false);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("QIA-QZKP"));
        assert!(content.contains("Aggregate"));
    }

    // ── print_terminal ────────────────────────────────────────────────────────

    #[test]
    fn print_terminal_single_qkd_no_panic() {
        let runs = vec![RunData::Qkd(make_qkd("BB84", None, false, true))];
        print_terminal(&runs, 1, false);
    }

    #[test]
    fn print_terminal_single_auth_no_panic() {
        let runs = vec![RunData::Auth(make_auth(false, true, 0.0))];
        print_terminal(&runs, 1, false);
    }

    #[test]
    fn print_terminal_multi_shot_no_panic() {
        let runs = vec![
            RunData::Qkd(make_qkd("BB84", None, false, true)),
            RunData::Qkd(make_qkd("BB84", None, false, true)),
        ];
        print_terminal(&runs, 2, false);
    }

    #[test]
    fn print_terminal_multi_shot_with_detail_no_panic() {
        let runs = vec![
            RunData::Qkd(make_qkd("BB84", None, false, true)),
            RunData::Qkd(make_qkd("BB84", None, false, true)),
        ];
        print_terminal(&runs, 2, true);
    }
}

// ── Terminal output ───────────────────────────────────────────────────────────

pub fn print_terminal(runs: &[RunData], shots: usize, detail: bool) {
    if shots == 1 {
        // Single shot: always show full run; keys included if --detail
        match &runs[0] {
            RunData::Qkd(r) => print!("{}", fmt_qkd_run(r, 1)),
            RunData::Auth(r) => print!("{}", fmt_auth_run(r, 1)),
        }
    } else {
        let agg = stats::compute(runs);
        print!("{}", stats::fmt(&agg));
        if detail {
            println!("  (per-run detail + keys written to output file)");
        }
    }
}
