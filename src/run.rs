use indicatif::{ProgressBar, ProgressStyle};
use qcrypto::{
    QuantumChannel,
    protocols::{b92, bb84, bbm92, e91, gc01, qia_qzkp, sarg04, six_state},
};
use rayon::prelude::*;

use crate::channel::ChannelInfo;

// ── Result types ──────────────────────────────────────────────────────────────

pub struct QkdRun {
    pub protocol: &'static str,
    pub shot: usize,
    pub channel: ChannelInfo,
    pub channel_bob: Option<ChannelInfo>,
    pub raw_length: usize,
    pub sifted: usize,
    pub check_errors: usize,
    pub qber: f64,
    pub qber_available: bool,
    pub eve_count: usize,
    pub key_length: usize,
    pub keys_match: bool,
    pub chsh_value: Option<f64>,
    pub alice_key_hex: Option<String>,
    pub bob_key_hex: Option<String>,
}

pub struct AuthRun {
    pub shot: usize,
    pub channel: ChannelInfo,
    pub total_qubits: usize,
    pub matches: usize,
    pub accuracy: f64,
    pub authenticated: bool,
    pub alice_id_hex: Option<String>,
    pub alice_commitment_hex: Option<String>,
    pub bob_challenge_hex: Option<String>,
    pub bob_recovered_hex: Option<String>,
}

pub struct QdsRun {
    pub shot: usize,
    pub channel_bob: ChannelInfo,
    pub channel_charlie: ChannelInfo,
    pub num_qubits: usize,
    pub message: bool,
    pub bob_mismatches: usize,
    pub charlie_mismatches: usize,
    pub bob_mismatch_rate: f64,
    pub charlie_mismatch_rate: f64,
    pub signature_accepted: bool,
    pub eve_intercepted_count: usize,
}

pub enum RunData {
    Qkd(QkdRun),
    Auth(AuthRun),
    Qds(QdsRun),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn to_hex(bits: &[bool]) -> String {
    if bits.is_empty() {
        return "(empty)".into();
    }
    bits.chunks(8)
        .map(|chunk| {
            let byte: u8 = chunk
                .iter()
                .enumerate()
                .fold(0u8, |acc, (i, &v)| acc | ((v as u8) << (7 - i)));
            format!("{byte:02x}")
        })
        .collect()
}

pub fn keys_equal(a: &[bool], b: &[bool]) -> bool {
    a == b
}

// ── Per-shot runners ──────────────────────────────────────────────────────────

pub fn run_bb84(
    shot: usize,
    n: usize,
    ch: &QuantumChannel,
    ch_info: ChannelInfo,
    eve: f64,
    check: f64,
    detail: bool,
    par: bool,
) -> RunData {
    let r = if par {
        bb84::run_par(n, ch, eve, check)
    } else {
        bb84::run(n, ch, eve, check)
    }
    .unwrap();
    RunData::Qkd(QkdRun {
        protocol: "BB84",
        shot,
        channel: ch_info,
        channel_bob: None,
        raw_length: r.raw_length,
        sifted: r.total_sifted,
        check_errors: r.check_errors,
        qber: r.qber,
        qber_available: true,
        eve_count: r.eve_intercepted_count,
        key_length: r.alice_key.len(),
        keys_match: keys_equal(&r.alice_key, &r.bob_key),
        chsh_value: None,
        alice_key_hex: detail.then(|| to_hex(&r.alice_key)),
        bob_key_hex: detail.then(|| to_hex(&r.bob_key)),
    })
}

pub fn run_b92(
    shot: usize,
    n: usize,
    ch: &QuantumChannel,
    ch_info: ChannelInfo,
    eve: f64,
    check: f64,
    detail: bool,
    par: bool,
) -> RunData {
    let measurement = b92::build_optimal_povm_b92().unwrap();
    let r = if par {
        b92::run_par(n, ch, &measurement, eve, check)
    } else {
        b92::run(n, ch, &measurement, eve, check)
    }
    .unwrap();
    RunData::Qkd(QkdRun {
        protocol: "B92",
        shot,
        channel: ch_info,
        channel_bob: None,
        raw_length: r.raw_length,
        sifted: r.conclusive_count,
        check_errors: r.check_errors,
        qber: r.qber,
        qber_available: true,
        eve_count: r.eve_intercepted_count,
        key_length: r.alice_key.len(),
        keys_match: keys_equal(&r.alice_key, &r.bob_key),
        chsh_value: None,
        alice_key_hex: detail.then(|| to_hex(&r.alice_key)),
        bob_key_hex: detail.then(|| to_hex(&r.bob_key)),
    })
}

pub fn run_bbm92(
    shot: usize,
    n: usize,
    ch_a: &QuantumChannel,
    ch_b: &QuantumChannel,
    ch_info_a: ChannelInfo,
    ch_info_b: ChannelInfo,
    eve: f64,
    check: f64,
    detail: bool,
    par: bool,
) -> RunData {
    let r = if par {
        bbm92::run_par(n, ch_a, ch_b, eve, check)
    } else {
        bbm92::run(n, ch_a, ch_b, eve, check)
    }
    .unwrap();
    RunData::Qkd(QkdRun {
        protocol: "BBM92",
        shot,
        channel: ch_info_a,
        channel_bob: Some(ch_info_b),
        raw_length: r.raw_length,
        sifted: r.total_sifted,
        check_errors: r.check_errors,
        qber: r.qber,
        qber_available: true,
        eve_count: r.eve_intercept_count,
        key_length: r.alice_key.len(),
        keys_match: keys_equal(&r.alice_key, &r.bob_key),
        chsh_value: None,
        alice_key_hex: detail.then(|| to_hex(&r.alice_key)),
        bob_key_hex: detail.then(|| to_hex(&r.bob_key)),
    })
}

pub fn run_e91(
    shot: usize,
    n: usize,
    ch_a: &QuantumChannel,
    ch_b: &QuantumChannel,
    ch_info_a: ChannelInfo,
    ch_info_b: ChannelInfo,
    eve: f64,
    check: f64,
    detail: bool,
    par: bool,
) -> RunData {
    let r = if par {
        e91::run_par(n, ch_a, ch_b, eve, check)
    } else {
        e91::run(n, ch_a, ch_b, eve, check)
    }
    .unwrap();
    let (qber_val, qber_avail) = r.qber.map_or((0.0, false), |q| (q, true));
    RunData::Qkd(QkdRun {
        protocol: "E91",
        shot,
        channel: ch_info_a,
        channel_bob: Some(ch_info_b),
        raw_length: r.raw_length,
        sifted: r.total_sifted,
        check_errors: r.check_errors,
        qber: qber_val,
        qber_available: qber_avail,
        eve_count: r.eve_intercept_count,
        key_length: r.alice_key.len(),
        keys_match: keys_equal(&r.alice_key, &r.bob_key),
        chsh_value: Some(r.chsh_value),
        alice_key_hex: detail.then(|| to_hex(&r.alice_key)),
        bob_key_hex: detail.then(|| to_hex(&r.bob_key)),
    })
}

pub fn run_six_state(
    shot: usize,
    n: usize,
    ch: &QuantumChannel,
    ch_info: ChannelInfo,
    eve: f64,
    check: f64,
    detail: bool,
    par: bool,
) -> RunData {
    let r = if par {
        six_state::run_par(n, ch, eve, check)
    } else {
        six_state::run(n, ch, eve, check)
    }
    .unwrap();
    RunData::Qkd(QkdRun {
        protocol: "Six-State",
        shot,
        channel: ch_info,
        channel_bob: None,
        raw_length: r.raw_length,
        sifted: r.total_sifted,
        check_errors: r.check_errors,
        qber: r.qber,
        qber_available: true,
        eve_count: r.eve_intercepted_count,
        key_length: r.alice_key.len(),
        keys_match: keys_equal(&r.alice_key, &r.bob_key),
        chsh_value: None,
        alice_key_hex: detail.then(|| to_hex(&r.alice_key)),
        bob_key_hex: detail.then(|| to_hex(&r.bob_key)),
    })
}

pub fn run_sarg04(
    shot: usize,
    n: usize,
    ch: &QuantumChannel,
    ch_info: ChannelInfo,
    eve: f64,
    check: f64,
    detail: bool,
    par: bool,
) -> RunData {
    let r = if par {
        sarg04::run_par(n, ch, eve, check)
    } else {
        sarg04::run(n, ch, eve, check)
    }
    .unwrap();
    RunData::Qkd(QkdRun {
        protocol: "SARG04",
        shot,
        channel: ch_info,
        channel_bob: None,
        raw_length: r.raw_length,
        sifted: r.conclusive_count,
        check_errors: r.check_errors,
        qber: r.qber,
        qber_available: true,
        eve_count: r.eve_intercepted_count,
        key_length: r.alice_key.len(),
        keys_match: keys_equal(&r.alice_key, &r.bob_key),
        chsh_value: None,
        alice_key_hex: detail.then(|| to_hex(&r.alice_key)),
        bob_key_hex: detail.then(|| to_hex(&r.bob_key)),
    })
}

pub fn run_gc01(
    shot: usize,
    n: usize,
    ch_bob: &QuantumChannel,
    ch_charlie: &QuantumChannel,
    ch_info_bob: ChannelInfo,
    ch_info_charlie: ChannelInfo,
    eve: f64,
    threshold: f64,
    par: bool,
) -> RunData {
    let r = if par {
        gc01::run_par(n, ch_bob, ch_charlie, eve, threshold)
    } else {
        gc01::run(n, ch_bob, ch_charlie, eve, threshold)
    }
    .unwrap();
    RunData::Qds(QdsRun {
        shot,
        channel_bob: ch_info_bob,
        channel_charlie: ch_info_charlie,
        num_qubits: r.num_qubits,
        message: r.message,
        bob_mismatches: r.bob_mismatches,
        charlie_mismatches: r.charlie_mismatches,
        bob_mismatch_rate: r.bob_mismatch_rate,
        charlie_mismatch_rate: r.charlie_mismatch_rate,
        signature_accepted: r.signature_accepted,
        eve_intercepted_count: r.eve_intercepted_count,
    })
}

pub fn run_qia_qzkp(
    shot: usize,
    n: usize,
    ch: &QuantumChannel,
    ch_info: ChannelInfo,
    threshold: f64,
    detail: bool,
    par: bool,
) -> RunData {
    let r = if par {
        qia_qzkp::run_par(n, ch, threshold)
    } else {
        qia_qzkp::run(n, ch, threshold)
    }
    .unwrap();
    RunData::Auth(AuthRun {
        shot,
        channel: ch_info,
        total_qubits: r.total_qubits,
        matches: r.matches,
        accuracy: r.accuracy,
        authenticated: r.authenticated,
        alice_id_hex: detail.then(|| to_hex(&r.alice_id_a)),
        alice_commitment_hex: detail.then(|| to_hex(&r.alice_commitment_b)),
        bob_challenge_hex: detail.then(|| to_hex(&r.bob_challenge_c)),
        bob_recovered_hex: detail.then(|| to_hex(&r.bob_recovered_c)),
    })
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{ChannelInfo, sample_channel, single_channel_mix};

    fn noop_info() -> ChannelInfo {
        ChannelInfo {
            type_name: "bit-flip".into(),
            p: 0.0,
            q: 0.0,
        }
    }

    fn zero_ch() -> QuantumChannel {
        let mix = single_channel_mix(&crate::channel::ChannelKind::BitFlip, Some(0.0), None);
        let (ch, _) = sample_channel(&mix);
        ch
    }

    // ── par=false path for every runner ──────────────────────────────────────

    #[test]
    fn run_bb84_sequential() {
        qcrypto::rng::set_global_seed(1);
        let ch = zero_ch();
        let rd = run_bb84(0, 100, &ch, noop_info(), 0.0, 0.5, false, false);
        assert!(matches!(rd, RunData::Qkd(_)));
    }

    #[test]
    fn run_b92_sequential() {
        qcrypto::rng::set_global_seed(2);
        let ch = zero_ch();
        let rd = run_b92(0, 100, &ch, noop_info(), 0.0, 0.5, false, false);
        assert!(matches!(rd, RunData::Qkd(_)));
    }

    #[test]
    fn run_bbm92_sequential() {
        qcrypto::rng::set_global_seed(3);
        let ch = zero_ch();
        let rd = run_bbm92(
            0,
            100,
            &ch,
            &ch,
            noop_info(),
            noop_info(),
            0.0,
            0.5,
            false,
            false,
        );
        assert!(matches!(rd, RunData::Qkd(_)));
    }

    #[test]
    fn run_e91_sequential() {
        qcrypto::rng::set_global_seed(4);
        let ch = zero_ch();
        let rd = run_e91(
            0,
            100,
            &ch,
            &ch,
            noop_info(),
            noop_info(),
            0.0,
            0.5,
            false,
            false,
        );
        assert!(matches!(rd, RunData::Qkd(_)));
    }

    #[test]
    fn run_six_state_sequential() {
        qcrypto::rng::set_global_seed(5);
        let ch = zero_ch();
        let rd = run_six_state(0, 100, &ch, noop_info(), 0.0, 0.5, false, false);
        assert!(matches!(rd, RunData::Qkd(_)));
    }

    #[test]
    fn run_sarg04_sequential() {
        qcrypto::rng::set_global_seed(6);
        let ch = zero_ch();
        let rd = run_sarg04(0, 100, &ch, noop_info(), 0.0, 0.5, false, false);
        assert!(matches!(rd, RunData::Qkd(_)));
    }

    #[test]
    fn run_qia_qzkp_sequential() {
        qcrypto::rng::set_global_seed(7);
        let ch = zero_ch();
        let rd = run_qia_qzkp(0, 50, &ch, noop_info(), 0.9, false, false);
        assert!(matches!(rd, RunData::Auth(_)));
    }

    #[test]
    fn run_gc01_sequential() {
        qcrypto::rng::set_global_seed(8);
        let ch = zero_ch();
        let rd = run_gc01(0, 50, &ch, &ch, noop_info(), noop_info(), 0.0, 0.1, false);
        assert!(matches!(rd, RunData::Qds(_)));
    }

    #[test]
    fn run_gc01_parallel() {
        qcrypto::rng::set_global_seed(9);
        let ch = zero_ch();
        let rd = run_gc01(0, 50, &ch, &ch, noop_info(), noop_info(), 0.0, 0.1, true);
        assert!(matches!(rd, RunData::Qds(_)));
    }

    #[test]
    fn run_gc01_records_channel_info() {
        qcrypto::rng::set_global_seed(15);
        let ch = zero_ch();
        let info_b = ChannelInfo {
            type_name: "depolarizing".into(),
            p: 0.02,
            q: 0.0,
        };
        let info_c = ChannelInfo {
            type_name: "phase-flip".into(),
            p: 0.03,
            q: 0.0,
        };
        let j =
            crate::output::run_to_json(&run_gc01(0, 50, &ch, &ch, info_b, info_c, 0.0, 0.1, true));
        assert_eq!(j["channel_bob_type"], "depolarizing");
        assert_eq!(j["channel_charlie_type"], "phase-flip");
    }

    #[test]
    fn run_gc01_noiseless_accepted() {
        qcrypto::rng::set_global_seed(16);
        let ch = zero_ch();
        let j = crate::output::run_to_json(&run_gc01(
            0,
            100,
            &ch,
            &ch,
            noop_info(),
            noop_info(),
            0.0,
            0.1,
            true,
        ));
        assert_eq!(j["signature_accepted"], true);
        assert_eq!(j["bob_mismatches"], 0);
        assert_eq!(j["charlie_mismatches"], 0);
    }

    // ── detail flag populates hex fields ─────────────────────────────────────

    #[test]
    fn run_bb84_detail_true_populates_keys() {
        qcrypto::rng::set_global_seed(10);
        let ch = zero_ch();
        let rd = run_bb84(0, 200, &ch, noop_info(), 0.0, 0.5, true, true);
        // Use run_to_json to inspect fields without pattern-matching the enum
        let j = crate::output::run_to_json(&rd);
        assert!(
            j["alice_key_hex"].is_string(),
            "alice_key_hex should be present with detail=true"
        );
        assert!(
            j["bob_key_hex"].is_string(),
            "bob_key_hex should be present with detail=true"
        );
    }

    #[test]
    fn run_bb84_detail_false_no_keys() {
        qcrypto::rng::set_global_seed(11);
        let ch = zero_ch();
        let rd = run_bb84(0, 200, &ch, noop_info(), 0.0, 0.5, false, true);
        let j = crate::output::run_to_json(&rd);
        assert!(
            j.get("alice_key_hex").is_none(),
            "alice_key_hex should be absent with detail=false"
        );
    }

    // ── channel info is recorded ──────────────────────────────────────────────

    #[test]
    fn runner_records_channel_info() {
        qcrypto::rng::set_global_seed(20);
        let ch = zero_ch();
        let info = ChannelInfo {
            type_name: "depolarizing".into(),
            p: 0.05,
            q: 0.0,
        };
        let rd = run_bb84(0, 100, &ch, info, 0.0, 0.5, false, true);
        let j = crate::output::run_to_json(&rd);
        assert_eq!(j["channel_type"], "depolarizing");
        assert!((j["channel_p"].as_f64().unwrap() - 0.05).abs() < 1e-12);
    }

    // ── detail=true for all remaining runners ────────────────────────────────

    #[test]
    fn run_b92_detail_true() {
        qcrypto::rng::set_global_seed(30);
        let ch = zero_ch();
        let j =
            crate::output::run_to_json(&run_b92(0, 200, &ch, noop_info(), 0.0, 0.5, true, true));
        assert!(j["alice_key_hex"].is_string());
    }

    #[test]
    fn run_bbm92_detail_true() {
        qcrypto::rng::set_global_seed(31);
        let ch = zero_ch();
        let j = crate::output::run_to_json(&run_bbm92(
            0,
            200,
            &ch,
            &ch,
            noop_info(),
            noop_info(),
            0.0,
            0.5,
            true,
            true,
        ));
        assert!(j["alice_key_hex"].is_string());
    }

    #[test]
    fn run_e91_detail_true() {
        qcrypto::rng::set_global_seed(32);
        let ch = zero_ch();
        let j = crate::output::run_to_json(&run_e91(
            0,
            200,
            &ch,
            &ch,
            noop_info(),
            noop_info(),
            0.0,
            0.5,
            true,
            true,
        ));
        assert!(j["alice_key_hex"].is_string());
    }

    #[test]
    fn run_six_state_detail_true() {
        qcrypto::rng::set_global_seed(33);
        let ch = zero_ch();
        let j = crate::output::run_to_json(&run_six_state(
            0,
            200,
            &ch,
            noop_info(),
            0.0,
            0.5,
            true,
            true,
        ));
        assert!(j["alice_key_hex"].is_string());
    }

    #[test]
    fn run_sarg04_detail_true() {
        qcrypto::rng::set_global_seed(34);
        let ch = zero_ch();
        let j =
            crate::output::run_to_json(&run_sarg04(0, 200, &ch, noop_info(), 0.0, 0.5, true, true));
        assert!(j["alice_key_hex"].is_string());
    }

    #[test]
    fn run_qia_qzkp_detail_true() {
        qcrypto::rng::set_global_seed(35);
        let ch = zero_ch();
        let j = crate::output::run_to_json(&run_qia_qzkp(0, 50, &ch, noop_info(), 0.9, true, true));
        assert!(j["alice_id_hex"].is_string());
    }

    // ── execute_shots ─────────────────────────────────────────────────────────

    #[test]
    fn execute_shots_no_seed_runs_all() {
        let ch = zero_ch();
        let results = execute_shots(3, None, |i, par| {
            run_bb84(i, 50, &ch, noop_info(), 0.0, 0.5, false, par)
        });
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn execute_shots_with_seed_is_deterministic() {
        let ch = zero_ch();
        let run = |seed| {
            execute_shots(4, Some(seed), |i, par| {
                run_bb84(i, 50, &ch, noop_info(), 0.0, 0.5, false, par)
            })
        };
        let a = run(42);
        let b = run(42);
        for (ra, rb) in a.iter().zip(b.iter()) {
            let ja = crate::output::run_to_json(ra);
            let jb = crate::output::run_to_json(rb);
            assert_eq!(ja["key_length"], jb["key_length"]);
        }
    }

    // ── to_hex / keys_equal ───────────────────────────────────────────────────

    #[test]
    fn to_hex_empty() {
        assert_eq!(to_hex(&[]), "(empty)");
    }

    #[test]
    fn to_hex_full_byte_all_ones() {
        // 8 × true = 0xFF
        let bits = [true; 8];
        assert_eq!(to_hex(&bits), "ff");
    }

    #[test]
    fn to_hex_full_byte_alternating() {
        // 10101010 = 0xAA
        let bits = [true, false, true, false, true, false, true, false];
        assert_eq!(to_hex(&bits), "aa");
    }

    #[test]
    fn to_hex_single_bit_msb() {
        // 1000_0000 = 0x80
        let bits = [true, false, false, false, false, false, false, false];
        assert_eq!(to_hex(&bits), "80");
    }

    #[test]
    fn to_hex_lsb_only() {
        // 0000_0001 = 0x01
        let bits = [false, false, false, false, false, false, false, true];
        assert_eq!(to_hex(&bits), "01");
    }

    #[test]
    fn to_hex_two_bytes() {
        let byte1 = [true, false, true, false, true, false, true, false]; // 0xAA
        let byte2 = [false, true, false, true, false, true, false, true]; // 0x55
        let bits: Vec<bool> = byte1.into_iter().chain(byte2).collect();
        assert_eq!(to_hex(&bits), "aa55");
    }

    #[test]
    fn to_hex_partial_byte() {
        // Only 4 bits [1,0,1,0] → chunk of 4 → 1010_0000 = 0xA0
        let bits = [true, false, true, false];
        assert_eq!(to_hex(&bits), "a0");
    }

    #[test]
    fn keys_equal_both_empty() {
        assert!(keys_equal(&[], &[]));
    }

    #[test]
    fn keys_equal_identical() {
        assert!(keys_equal(&[true, false, true], &[true, false, true]));
    }

    #[test]
    fn keys_equal_different_value() {
        assert!(!keys_equal(&[true, false], &[true, true]));
    }

    #[test]
    fn keys_equal_different_length() {
        assert!(!keys_equal(&[true], &[true, false]));
    }
}

// ── Shots loop with progress bar ──────────────────────────────────────────────

pub fn execute_shots<F>(shots: usize, seed: Option<u64>, run_one: F) -> Vec<RunData>
where
    F: Fn(usize, bool) -> RunData + Send + Sync,
{
    // Always use run_par (not run) for protocol execution.
    // qcrypto's DensityMatrix::apply_channel uses par_iter() internally even in the
    // sequential `run` path. When across-shots rayon tasks are pending, a worker
    // thread can steal an outer shot task during that inner par_iter — overwriting the
    // thread-local RNG before the current shot calls shuffle_slice, making results
    // non-deterministic. run_par draws master_seed before spawning any inner tasks and
    // uses LocalRng::child per qubit, so the thread-local is only consumed once and
    // shuffle_slice sees a consistent state.
    let use_par_inner = true;

    let pb: Option<ProgressBar> = if shots > 1 {
        let bar = ProgressBar::new(shots as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} [{elapsed_precise}] [{bar:42.cyan/blue}] {pos}/{len} shots  (ETA {eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        Some(bar)
    } else {
        None
    };

    let results: Vec<RunData> = (0..shots)
        .into_par_iter()
        .map(|i| {
            if let Some(s) = seed {
                qcrypto::rng::set_global_seed(s + i as u64);
            }
            let result = run_one(i, use_par_inner);
            if let Some(ref bar) = pb {
                bar.inc(1);
            }
            result
        })
        .collect();

    if let Some(bar) = pb {
        bar.finish_and_clear();
    }
    results
}
