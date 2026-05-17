//! Integration tests — run the compiled binary and verify its behaviour.
//!
//! Each test is independent: it uses a temporary directory for output files
//! and a fixed `--seed` so results are deterministic.

use std::io::Write;
use std::process::Command;
use tempfile::{NamedTempFile, TempDir};

// ── Helper: path to the compiled binary ──────────────────────────────────────

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_qcryptool"))
}

// ── Helper: write a temp JSON channel config ──────────────────────────────────

fn write_channel_config(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "{content}").unwrap();
    f
}

fn multi_channel_config() -> NamedTempFile {
    write_channel_config(
        r#"[
          {"type":"bit-flip",    "p":0.01,"weight":0.6},
          {"type":"depolarizing","p":0.05,"weight":0.4}
        ]"#,
    )
}

// ── Basic invocation ──────────────────────────────────────────────────────────

#[test]
fn help_exits_zero() {
    let status = bin().arg("--help").status().unwrap();
    assert!(status.success());
}

#[test]
fn bb84_single_shot_exits_zero() {
    let status = bin()
        .args(["bb84", "-n", "200", "--seed", "1"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn b92_single_shot_exits_zero() {
    let status = bin()
        .args(["b92", "-n", "200", "--seed", "2"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn bbm92_single_shot_exits_zero() {
    let status = bin()
        .args(["bbm92", "-n", "200", "--seed", "3"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn e91_single_shot_exits_zero() {
    let status = bin()
        .args(["e91", "-n", "200", "--seed", "4"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn six_state_single_shot_exits_zero() {
    let status = bin()
        .args(["six-state", "-n", "200", "--seed", "5"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn sarg04_single_shot_exits_zero() {
    let status = bin()
        .args(["sarg04", "-n", "200", "--seed", "6"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn qia_qzkp_single_shot_exits_zero() {
    let status = bin()
        .args(["qia-qzkp", "-n", "50", "--seed", "7"])
        .status()
        .unwrap();
    assert!(status.success());
}

// ── Seed reproducibility ──────────────────────────────────────────────────────

fn csv_bytes(
    protocol: &str,
    extra_args: &[&str],
    n: &str,
    shots: &str,
    seed: &str,
    dir: &TempDir,
) -> Vec<u8> {
    let out = dir.path().join("out.csv");
    let status = bin()
        .arg(protocol)
        .args(["-n", n, "-s", shots, "--seed", seed])
        .args(extra_args)
        .args(["-o", out.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "protocol {protocol} failed");
    std::fs::read(&out).unwrap()
}

macro_rules! seed_repro_test {
    ($name:ident, $protocol:expr, $n:expr, $shots:expr) => {
        #[test]
        fn $name() {
            let d1 = TempDir::new().unwrap();
            let d2 = TempDir::new().unwrap();
            let a = csv_bytes($protocol, &[], $n, $shots, "42", &d1);
            let b = csv_bytes($protocol, &[], $n, $shots, "42", &d2);
            assert_eq!(a, b, "{} CSV differs between two seeded runs", $protocol);
        }
    };
}

seed_repro_test!(seed_repro_bb84, "bb84", "512", "16");
seed_repro_test!(seed_repro_b92, "b92", "512", "16");
seed_repro_test!(seed_repro_bbm92, "bbm92", "512", "16");
seed_repro_test!(seed_repro_e91, "e91", "512", "16");
seed_repro_test!(seed_repro_six_state, "six-state", "512", "16");
seed_repro_test!(seed_repro_sarg04, "sarg04", "512", "16");
seed_repro_test!(seed_repro_qia_qzkp, "qia-qzkp", "80", "16");

// ── CSV format ────────────────────────────────────────────────────────────────

#[test]
fn csv_has_channel_columns() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    let status = bin()
        .args([
            "bb84",
            "-n",
            "100",
            "-s",
            "3",
            "--seed",
            "10",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let content = std::fs::read_to_string(&out).unwrap();
    let header = content.lines().next().unwrap();
    assert!(
        header.contains("channel_type"),
        "missing channel_type in: {header}"
    );
    assert!(
        header.contains("channel_p"),
        "missing channel_p in: {header}"
    );
    assert!(
        header.contains("channel_p2"),
        "missing channel_p2 in: {header}"
    );
}

#[test]
fn csv_row_count_matches_shots() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    let shots = 7usize;
    bin()
        .args([
            "bb84",
            "-n",
            "100",
            "-s",
            &shots.to_string(),
            "--seed",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    let data_rows = content.lines().count() - 1; // subtract header
    assert_eq!(data_rows, shots);
}

#[test]
fn csv_detail_adds_key_columns() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    bin()
        .args([
            "bb84",
            "-n",
            "200",
            "--seed",
            "5",
            "--detail",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let header = std::fs::read_to_string(&out).unwrap();
    let hdr = header.lines().next().unwrap();
    assert!(hdr.contains("alice_key_hex"), "missing alice_key_hex");
    assert!(hdr.contains("bob_key_hex"), "missing bob_key_hex");
}

#[test]
fn csv_without_detail_has_no_key_columns() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    bin()
        .args([
            "bb84",
            "-n",
            "200",
            "--seed",
            "5",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    let hdr = content.lines().next().unwrap();
    assert!(
        !hdr.contains("alice_key_hex"),
        "unexpected alice_key_hex without --detail"
    );
}

#[test]
fn csv_noise_recorded_correctly() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    bin()
        .args([
            "bb84",
            "-n",
            "100",
            "--channel",
            "depolarizing",
            "--noise",
            "0.07",
            "--seed",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    // Every data row should record depolarizing as channel
    for line in content.lines().skip(1) {
        assert!(
            line.contains("depolarizing"),
            "expected depolarizing in row: {line}"
        );
    }
}

// ── JSON format ───────────────────────────────────────────────────────────────

#[test]
fn json_output_is_valid_json() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.json");
    bin()
        .args([
            "bb84",
            "-n",
            "200",
            "-s",
            "3",
            "--seed",
            "9",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("output is not valid JSON");
    assert!(parsed["aggregate"].is_object());
    assert!(parsed["runs"].is_array());
    assert_eq!(parsed["shots"], 3);
}

#[test]
fn json_run_has_channel_fields() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.json");
    bin()
        .args([
            "bb84",
            "-n",
            "200",
            "--seed",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let run = &parsed["runs"][0];
    assert!(run["channel_type"].is_string(), "missing channel_type");
    assert!(run["channel_p"].is_number(), "missing channel_p");
    assert!(run["channel_p2"].is_number(), "missing channel_p2");
}

// ── channel-config ────────────────────────────────────────────────────────────

#[test]
fn channel_config_valid_runs_successfully() {
    let cfg = multi_channel_config();
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    let status = bin()
        .args([
            "bb84",
            "-n",
            "200",
            "-s",
            "5",
            "--seed",
            "77",
            "--channel-config",
            cfg.path().to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn channel_config_records_sampled_types() {
    let cfg = multi_channel_config();
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    bin()
        .args([
            "bb84",
            "-n",
            "200",
            "-s",
            "30",
            "--seed",
            "7",
            "--channel-config",
            cfg.path().to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    let types: std::collections::HashSet<&str> = content
        .lines()
        .skip(1)
        .filter_map(|l| l.split(',').nth(1))
        .collect();
    // With 30 shots and seed=7, both channel types should appear
    assert!(
        types.contains("bit-flip"),
        "bit-flip never sampled in 30 shots"
    );
    assert!(
        types.contains("depolarizing"),
        "depolarizing never sampled in 30 shots"
    );
}

#[test]
fn channel_config_seed_reproducible() {
    let cfg = multi_channel_config();
    let dir1 = TempDir::new().unwrap();
    let dir2 = TempDir::new().unwrap();
    let out1 = dir1.path().join("out.csv");
    let out2 = dir2.path().join("out.csv");
    let args = ["bb84", "-n", "512", "-s", "12", "--seed", "55"];
    bin()
        .args(args)
        .args(["--channel-config", cfg.path().to_str().unwrap()])
        .args(["-o", out1.to_str().unwrap()])
        .status()
        .unwrap();
    bin()
        .args(args)
        .args(["--channel-config", cfg.path().to_str().unwrap()])
        .args(["-o", out2.to_str().unwrap()])
        .status()
        .unwrap();
    assert_eq!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&out2).unwrap(),
        "seeded channel-config run is not reproducible"
    );
}

#[test]
fn channel_config_missing_file_exits_nonzero() {
    let status = bin()
        .args([
            "bb84",
            "-n",
            "100",
            "--channel-config",
            "/nonexistent/path/missing.json",
        ])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn channel_config_invalid_json_exits_nonzero() {
    let cfg = write_channel_config("not valid json");
    let status = bin()
        .args([
            "bb84",
            "-n",
            "100",
            "--channel-config",
            cfg.path().to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn channel_config_empty_array_exits_nonzero() {
    let cfg = write_channel_config("[]");
    let status = bin()
        .args([
            "bb84",
            "-n",
            "100",
            "--channel-config",
            cfg.path().to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success());
}

// ── Noise ─────────────────────────────────────────────────────────────────────

#[test]
fn noise_zero_keys_always_match() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    bin()
        .args([
            "bb84",
            "-n",
            "500",
            "-s",
            "10",
            "--seed",
            "1",
            "--noise",
            "0.0",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    for line in content.lines().skip(1) {
        let keys_match = line.split(',').nth(11).unwrap_or("");
        assert_eq!(
            keys_match, "true",
            "keys should match with zero noise: {line}"
        );
    }
}

#[test]
fn noise_high_degrades_key_match_rate() {
    // p=0.5 depolarizing → nearly all keys should fail to match
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    bin()
        .args([
            "bb84",
            "-n",
            "500",
            "-s",
            "20",
            "--seed",
            "1",
            "--channel",
            "depolarizing",
            "--noise",
            "0.5",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    let total = content.lines().skip(1).count();
    let failed = content
        .lines()
        .skip(1)
        .filter(|l| l.split(',').nth(11).unwrap_or("") == "false")
        .count();
    assert!(
        failed > total / 2,
        "expected most keys to fail with 50% depolarizing noise"
    );
}

// ── TXT output ───────────────────────────────────────────────────────────────

#[test]
fn txt_output_contains_protocol_and_channel() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.txt");
    bin()
        .args([
            "bb84",
            "-n",
            "200",
            "-s",
            "2",
            "--seed",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(content.contains("Protocol"), "missing Protocol in txt");
    assert!(content.contains("Channel"), "missing Channel in txt");
    assert!(content.contains("BB84"), "missing BB84 in txt");
    assert!(
        content.contains("Aggregate"),
        "missing Aggregate block in txt"
    );
}

#[test]
fn txt_single_shot_no_aggregate() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.txt");
    bin()
        .args([
            "bb84",
            "-n",
            "200",
            "--seed",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(
        !content.contains("Aggregate"),
        "single shot should not have Aggregate block"
    );
}

// ── E91 CHSH CSV columns ──────────────────────────────────────────────────────

#[test]
fn e91_csv_has_chsh_columns() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    bin()
        .args([
            "e91",
            "-n",
            "300",
            "-s",
            "3",
            "--seed",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    let hdr = content.lines().next().unwrap();
    assert!(hdr.contains("chsh_value"), "missing chsh_value in E91 CSV");
    assert!(
        hdr.contains("bell_violated"),
        "missing bell_violated in E91 CSV"
    );
}

// ── qia-qzkp JSON ─────────────────────────────────────────────────────────────

#[test]
fn qia_qzkp_json_has_expected_fields() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.json");
    bin()
        .args([
            "qia-qzkp",
            "-n",
            "100",
            "-s",
            "2",
            "--seed",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    let j: serde_json::Value = serde_json::from_str(&content).unwrap();
    let run = &j["runs"][0];
    assert!(run["accuracy"].is_number(), "missing accuracy");
    assert!(run["authenticated"].is_boolean(), "missing authenticated");
    assert!(run["channel_type"].is_string(), "missing channel_type");
    assert_eq!(j["aggregate"]["protocol"], "QIA-QZKP");
}

// ── detail + multi-shot on terminal ──────────────────────────────────────────

#[test]
fn detail_multi_shot_prints_note() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    let output = bin()
        .args([
            "bb84",
            "-n",
            "200",
            "-s",
            "3",
            "--seed",
            "1",
            "--detail",
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("per-run detail") || stdout.contains("keys written"),
        "expected note about keys in file: {stdout}"
    );
}

// ── Auth TXT output ───────────────────────────────────────────────────────────

#[test]
fn qia_qzkp_txt_output_has_channel_and_protocol() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.txt");
    bin()
        .args([
            "qia-qzkp",
            "-n",
            "50",
            "-s",
            "2",
            "--seed",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(content.contains("QIA-QZKP"), "missing protocol in auth txt");
    assert!(content.contains("Channel"), "missing Channel in auth txt");
    assert!(
        content.contains("Aggregate"),
        "missing Aggregate block in auth txt"
    );
}

// ── All channel types via CLI ────────────────────────────────────────────────

macro_rules! channel_type_test {
    ($name:ident, $ch:expr) => {
        #[test]
        fn $name() {
            let dir = TempDir::new().unwrap();
            let out = dir.path().join("out.csv");
            let status = bin()
                .args([
                    "bb84",
                    "-n",
                    "100",
                    "--seed",
                    "1",
                    "--channel",
                    $ch,
                    "--noise",
                    "0.01",
                    "-o",
                    out.to_str().unwrap(),
                ])
                .status()
                .unwrap();
            assert!(status.success(), "channel {} failed", $ch);
            let content = std::fs::read_to_string(&out).unwrap();
            // channel_type column should contain the channel name
            assert!(
                content.contains($ch),
                "channel name not recorded in CSV for {}",
                $ch
            );
        }
    };
}

channel_type_test!(channel_phase_flip, "phase-flip");
channel_type_test!(channel_bit_phase_flip, "bit-phase-flip");
channel_type_test!(channel_depolarizing, "depolarizing");
channel_type_test!(channel_amplitude_damping, "amplitude-damping");
channel_type_test!(channel_phase_damping, "phase-damping");

#[test]
fn channel_amplitude_phase_damping() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    let status = bin()
        .args([
            "bb84",
            "-n",
            "100",
            "--seed",
            "1",
            "--channel",
            "amplitude-phase-damping",
            "--noise",
            "0.01",
            "--noise2",
            "0.01",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(content.contains("amplitude-phase-damping"));
}

// ── detail on single shot shows keys in terminal ─────────────────────────────

#[test]
fn detail_single_shot_shows_keys_in_stdout() {
    let output = bin()
        .args(["bb84", "-n", "300", "--seed", "42", "--detail"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Alice key") || stdout.contains("alice"),
        "expected key hex in terminal with --detail: {stdout}"
    );
}

// ── qia-qzkp specific ─────────────────────────────────────────────────────────

#[test]
fn qia_qzkp_csv_has_auth_columns() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    bin()
        .args([
            "qia-qzkp",
            "-n",
            "100",
            "-s",
            "3",
            "--seed",
            "1",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    let hdr = content.lines().next().unwrap();
    assert!(hdr.contains("accuracy"), "missing accuracy column");
    assert!(
        hdr.contains("authenticated"),
        "missing authenticated column"
    );
    assert!(hdr.contains("channel_type"), "missing channel_type column");
}

#[test]
fn qia_qzkp_noiseless_always_authenticates() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    bin()
        .args([
            "qia-qzkp",
            "-n",
            "200",
            "-s",
            "10",
            "--seed",
            "1",
            "--noise",
            "0.0",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    let content = std::fs::read_to_string(&out).unwrap();
    for line in content.lines().skip(1) {
        let auth = line.split(',').nth(7).unwrap_or("");
        assert_eq!(
            auth, "true",
            "expected authentication with zero noise: {line}"
        );
    }
}
