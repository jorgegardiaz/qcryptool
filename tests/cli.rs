//! Integration tests — run the compiled binary and verify its behaviour.
//!
//! Each test is independent: it uses a temporary directory for output files
//! and a fixed `--seed` so results are deterministic.

use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::{NamedTempFile, TempDir};

/// Helper to get the command for the compiled binary.
fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_qcryptool"));
    // Ensure we don't pick up a config from the user's home or something
    cmd.env_remove("QKD_CONFIG");
    cmd
}

// ── Basic protocols ──────────────────────────────────────────────────────────

#[test]
fn bb84_basic() {
    let output = bin().arg("bb84").arg("-n").arg("100").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BB84"));
}

#[test]
fn b92_basic() {
    let output = bin().arg("b92").arg("-n").arg("100").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("B92"));
}

#[test]
fn bbm92_basic() {
    let output = bin().arg("bbm92").arg("-n").arg("100").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BBM92"));
}

#[test]
fn e91_basic() {
    let output = bin().arg("e91").arg("-n").arg("100").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("E91"));
}

#[test]
fn six_state_basic() {
    let output = bin()
        .arg("six-state")
        .arg("-n")
        .arg("100")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Six-State"));
}

#[test]
fn sarg04_basic() {
    let output = bin().arg("sarg04").arg("-n").arg("100").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SARG04"));
}

#[test]
fn qia_qzkp_basic() {
    let output = bin().arg("qia-qzkp").arg("-n").arg("100").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("QIA-QZKP"));
}

#[test]
fn gc01_basic() {
    let output = bin().arg("gc01").arg("-n").arg("100").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("GC01"));
}

// ── Multi-shot aggregate ─────────────────────────────────────────────────────

#[test]
fn bb84_multi_shot() {
    let output = bin()
        .args(["bb84", "-n", "100", "-s", "5"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Aggregate (5 shots)"));
}

// ── Seeds and Reproducibility ───────────────────────────────────────────────

macro_rules! seed_test {
    ($name:ident, $proto:expr) => {
        #[test]
        fn $name() {
            let out1 = bin()
                .args([$proto, "-n", "50", "--seed", "12345"])
                .output()
                .unwrap();
            let out2 = bin()
                .args([$proto, "-n", "50", "--seed", "12345"])
                .output()
                .unwrap();
            assert_eq!(out1.stdout, out2.stdout);
        }
    };
}

seed_test!(seed_repro_bb84, "bb84");
seed_test!(seed_repro_b92, "b92");
seed_test!(seed_repro_bbm92, "bbm92");
seed_test!(seed_repro_e91, "e91");
seed_test!(seed_repro_six_state, "six-state");
seed_test!(seed_repro_sarg04, "sarg04");
seed_test!(seed_repro_gc01, "gc01");

// ── Channel mixing ───────────────────────────────────────────────────────────

#[test]
fn channel_mix_from_file() {
    let mut f = NamedTempFile::new().unwrap();
    // JSON with 100% bit-flip
    f.write_all(br#"[ {"type": "bit-flip", "p": 0.1, "weight": 1.0} ]"#)
        .unwrap();

    let output = bin()
        .args([
            "bb84",
            "-n",
            "10",
            "--channel-config",
            f.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bit-flip"));
}

// ── Output files ─────────────────────────────────────────────────────────────

#[test]
fn output_csv() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("res.csv");

    let status = bin()
        .args(["bb84", "-n", "10", "-o", file_path.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(file_path.exists());

    let content = std::fs::read_to_string(file_path).unwrap();
    assert!(content.contains("shot,channel_type"));
}

#[test]
fn output_json() {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("res.json");

    let status = bin()
        .args(["bb84", "-n", "10", "-o", file_path.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let content = std::fs::read_to_string(file_path).unwrap();
    assert!(content.starts_with('{'));
    assert!(content.contains("\"shot\": 1"));
}

// ── Detail / keys ───────────────────────────────────────────────────────────

#[test]
fn detail_mode_shows_keys() {
    let output = bin()
        .args(["bb84", "-n", "10", "--detail"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Alice key (hex)"));
    assert!(stdout.contains("Bob key (hex)"));
}

#[test]
fn multi_shot_detail_saves_keys_to_csv() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("keys.csv");
    let status = bin()
        .args([
            "bb84",
            "-n",
            "10",
            "-s",
            "2",
            "--detail",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let content = std::fs::read_to_string(out).unwrap();
    assert!(content.contains("alice_key_hex"));
}

// ── Auth protocol (QIA-QZKP) ────────────────────────────────────────────────

#[test]
fn qia_qzkp_detail() {
    let output = bin()
        .args(["qia-qzkp", "-n", "10", "--detail"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Alice id 'a'"));
}

#[test]
fn qia_qzkp_csv_detail() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("auth.csv");
    let status = bin()
        .args([
            "qia-qzkp",
            "-n",
            "10",
            "-s",
            "2",
            "--detail",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let content = std::fs::read_to_string(out).unwrap();
    assert!(content.contains("alice_id_hex"));
}

// ── experiment-config ─────────────────────────────────────────────────────────

#[test]
fn experiment_config_works_without_subcommand() {
    let mut f = NamedTempFile::new().unwrap();
    write!(
        f,
        r#"{{
        "protocol": "bb84",
        "num_qubits": 100,
        "shots": 2,
        "seed": 1,
        "channel1": "depolarizing",
        "p1": 0.01
    }}"#
    )
    .unwrap();

    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "experiment-config failed");
}

#[test]
fn experiment_config_overrides_subcommand_protocol() {
    let mut f = NamedTempFile::new().unwrap();
    write!(
        f,
        r#"{{
        "protocol": "bb84",
        "num_qubits": 100
    }}"#
    )
    .unwrap();

    // Even if we say 'b92' on CLI, the config says 'bb84'
    let output = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .arg("b92")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success());
    assert!(stdout.contains("BB84"), "should have run BB84 from config");
    assert!(
        stderr.contains("Warning"),
        "should have warned about mismatch"
    );
}

#[test]
fn experiment_config_keys_out_controls_file_output() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("out.csv");
    let mut f = NamedTempFile::new().unwrap();
    write!(
        f,
        r#"{{
        "protocol": "bb84",
        "num_qubits": 100,
        "out_file": "{path}",
        "keys_out": true,
        "detail": false
    }}"#,
        path = out.to_str().unwrap().replace("\\", "\\\\")
    )
    .unwrap();

    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let content = std::fs::read_to_string(&out).unwrap();
    let header = content.lines().next().unwrap();
    assert!(
        header.contains("alice_key_hex"),
        "keys_out: true should add alice_key_hex to CSV"
    );
}

#[test]
fn all_protocols_via_experiment_config() {
    let protocols = [
        "bb84",
        "b92",
        "bbm92",
        "e91",
        "six-state",
        "sarg04",
        "qia-qzkp",
        "gc01",
    ];
    for p in protocols {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"{{"protocol": "{p}", "num_qubits": 10, "shots": 1}}"#).unwrap();
        let status = bin()
            .args(["--experiment-config", f.path().to_str().unwrap()])
            .status()
            .unwrap();
        assert!(status.success(), "failed for protocol {p}");

        // Also test with explicit subcommand to hit Some(Command) branch
        let status2 = bin()
            .args(["--experiment-config", f.path().to_str().unwrap(), p])
            .status()
            .unwrap();
        assert!(status2.success(), "failed for protocol {p} with subcommand");
    }
}

#[test]
fn experiment_config_with_channel_mix_file() {
    let mut mix_file = NamedTempFile::new().unwrap();
    mix_file
        .write_all(br#"[ {"type": "bit-flip", "p": 0.05}, {"type": "phase-flip", "p": 0.02} ]"#)
        .unwrap();

    let mut config_file = NamedTempFile::new().unwrap();
    write!(
        config_file,
        r#"{{
        "protocol": "bb84",
        "num_qubits": 10,
        "shots": 1,
        "channel_config_file": "{path}"
    }}"#,
        path = mix_file.path().to_str().unwrap().replace("\\", "\\\\")
    )
    .unwrap();

    let status = bin()
        .args(["--experiment-config", config_file.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn cli_help_message() {
    let output = bin().arg("--help").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}

#[test]
fn cli_no_args_shows_help() {
    let output = bin().output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
}

#[test]
fn error_missing_experiment_config() {
    let status = bin()
        .args(["--experiment-config", "nonexistent.json"])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn error_invalid_experiment_config_json() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "not json").unwrap();
    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn error_missing_protocol_in_experiment_config() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, r#"{{"num_qubits": 10}}"#).unwrap();
    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn experiment_config_missing_protocol_but_has_subcommand() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, r#"{{"num_qubits": 10}}"#).unwrap();
    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap(), "bb84"])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn error_unknown_protocol_in_experiment_config() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, r#"{{"protocol": "unknown"}}"#).unwrap();
    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn error_missing_p1_for_noise_channel() {
    let status = bin()
        .args(["bb84", "--channel1", "bit-flip"])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn error_missing_q1_for_combined_channel() {
    let status = bin()
        .args([
            "bb84",
            "--channel1",
            "amplitude-phase-damping",
            "--p1",
            "0.1",
        ])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn error_invalid_channel_config_file() {
    let status = bin()
        .args(["bb84", "--channel-config", "nonexistent_mix.json"])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn error_empty_channel_config_array() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "[]").unwrap();
    // Wait, if we use subcommand, it uses resolve_mix which might hit load_channel_mix []
    // but experiment config uses primary_mix which hits resolve_mix_from_parts
    let mut f2 = NamedTempFile::new().unwrap();
    write!(f2, r#"{{"protocol": "bb84", "channel_config": []}}"#).unwrap();
    let status2 = bin()
        .args(["--experiment-config", f2.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status2.success());
}

#[test]
fn error_missing_p1_in_experiment_config() {
    let mut f = NamedTempFile::new().unwrap();
    write!(
        f,
        r#"{{
        "protocol": "bb84",
        "channel1": "bit-flip"
    }}"#
    )
    .unwrap();
    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn error_missing_q1_in_experiment_config() {
    let mut f = NamedTempFile::new().unwrap();
    write!(
        f,
        r#"{{
        "protocol": "bb84",
        "channel1": "amplitude-phase-damping",
        "p1": 0.05
    }}"#
    )
    .unwrap();
    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn error_invalid_channel_config_file_in_experiment_config() {
    let mut f = NamedTempFile::new().unwrap();
    write!(
        f,
        r#"{{
        "protocol": "bb84",
        "channel_config_file": "nonexistent.json"
    }}"#
    )
    .unwrap();
    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn error_invalid_channel_config2_file_in_experiment_config() {
    let mut f = NamedTempFile::new().unwrap();
    write!(
        f,
        r#"{{
        "protocol": "e91",
        "channel_config2_file": "nonexistent.json"
    }}"#
    )
    .unwrap();
    let status = bin()
        .args(["--experiment-config", f.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn warning_protocol_mismatch() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, r#"{{"protocol": "bb84"}}"#).unwrap();
    let output = bin()
        .args(["--experiment-config", f.path().to_str().unwrap(), "b92"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Warning"));
}

// ── All channel types via CLI ────────────────────────────────────────────────

macro_rules! channel_type_test {
    ($name:ident, $ch:expr) => {
        #[test]
        fn $name() {
            let dir = TempDir::new().unwrap();
            let out = dir.path().join("res.csv");
            let status = bin()
                .args([
                    "bb84",
                    "-n",
                    "10",
                    "--channel1",
                    $ch,
                    "--p1",
                    "0.05",
                    "-o",
                    out.to_str().unwrap(),
                ])
                .status()
                .unwrap();
            assert!(status.success(), "failed for channel {}", $ch);
        }
    };
}

channel_type_test!(ch_bit_flip, "bit-flip");
channel_type_test!(ch_phase_flip, "phase-flip");
channel_type_test!(ch_bit_phase_flip, "bit-phase-flip");
channel_type_test!(ch_depolarizing, "depolarizing");
channel_type_test!(ch_amplitude_damping, "amplitude-damping");
channel_type_test!(ch_phase_damping, "phase-damping");

#[test]
fn ch_amplitude_phase_damping() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("res.csv");
    let status = bin()
        .args([
            "bb84",
            "-n",
            "10",
            "--channel1",
            "amplitude-phase-damping",
            "--p1",
            "0.05",
            "--q1",
            "0.02",
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
}
