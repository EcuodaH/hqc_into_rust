/// Profiling binary pour les KATs HQC.
///
/// Usage :
///   profile_kats time [N]          — mesure timing/mémoire sur N KATs (défaut 100), JSON sur stdout
///   profile_kats graph [op]        — exécute op (keypair|enc|dec|all) pour callgrind

use std::time::Instant;
use hqc::parameters::*;
use hqc::kem;
use hqc::symmetric;

const KAT_RSP: &str = include_str!("../../tests/PQCkemKAT_2321.rsp");

fn rss_kb() -> i64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn hwm_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn parse_seeds(limit: usize) -> Vec<Vec<u8>> {
    KAT_RSP
        .lines()
        .filter_map(|l| l.strip_prefix("seed = "))
        .take(limit)
        .map(|v| hex::decode(v).expect("hex invalide dans le fichier KAT"))
        .collect()
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p / 100.0).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn stats_block(label: &str, times_ns: &[u64], rss_deltas_kb: &[i64]) -> String {
    let mut sorted = times_ns.to_vec();
    sorted.sort_unstable();

    let n = sorted.len() as f64;
    let mean = sorted.iter().sum::<u64>() as f64 / n;
    let std_dev = (sorted
        .iter()
        .map(|&x| {
            let d = x as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / n)
        .sqrt();

    let times_str = times_ns
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let rss_str = rss_deltas_kb
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"  "{label}": {{
    "times_ns":    [{times}],
    "rss_delta_kb": [{rss}],
    "min_ns":    {min},
    "max_ns":    {max},
    "mean_ns":   {mean:.0},
    "median_ns": {median},
    "p25_ns":    {p25},
    "p75_ns":    {p75},
    "p95_ns":    {p95},
    "std_ns":    {std:.0}
  }}"#,
        label = label,
        times = times_str,
        rss = rss_str,
        min = sorted[0],
        max = *sorted.last().unwrap(),
        mean = mean,
        median = percentile(&sorted, 50.0),
        p25 = percentile(&sorted, 25.0),
        p75 = percentile(&sorted, 75.0),
        p95 = percentile(&sorted, 95.0),
        std = std_dev,
    )
}

// ---------------------------------------------------------------------------
// Mode timing : mesure wall-time et VmRSS par opération
// ---------------------------------------------------------------------------

fn run_timing(n: usize) {
    let seeds = parse_seeds(n);
    let n = seeds.len();
    eprintln!("Profiling {} KATs...", n);

    let mut kp_times: Vec<u64> = Vec::with_capacity(n);
    let mut enc_times: Vec<u64> = Vec::with_capacity(n);
    let mut dec_times: Vec<u64> = Vec::with_capacity(n);
    let mut kp_rss: Vec<i64> = Vec::with_capacity(n);
    let mut enc_rss: Vec<i64> = Vec::with_capacity(n);
    let mut dec_rss: Vec<i64> = Vec::with_capacity(n);

    for (i, seed) in seeds.iter().enumerate() {
        if (i + 1) % 20 == 0 || i + 1 == n {
            eprintln!("  [{}/{}]", i + 1, n);
        }

        let mut ctx = symmetric::prng_init(seed, &[]);
        let mut ek_kem = vec![0u8; PUBLIC_KEY_BYTES];
        let mut dk_kem = vec![0u8; SECRET_KEY_BYTES];
        let mut ct = vec![0u8; CIPHERTEXT_BYTES];
        let mut ss = vec![0u8; SHARED_SECRET_BYTES];
        let mut ss_dec = vec![0u8; SHARED_SECRET_BYTES];

        let r0 = rss_kb();
        let t = Instant::now();
        kem::crypto_kem_keypair(&mut ek_kem, &mut dk_kem, &mut ctx);
        kp_times.push(t.elapsed().as_nanos() as u64);
        kp_rss.push(rss_kb() - r0);

        let r0 = rss_kb();
        let t = Instant::now();
        kem::crypto_kem_enc(&mut ct, &mut ss, &ek_kem, &mut ctx);
        enc_times.push(t.elapsed().as_nanos() as u64);
        enc_rss.push(rss_kb() - r0);

        let r0 = rss_kb();
        let t = Instant::now();
        kem::crypto_kem_dec(&mut ss_dec, &ct, &dk_kem);
        dec_times.push(t.elapsed().as_nanos() as u64);
        dec_rss.push(rss_kb() - r0);
    }

    println!(
        "{{\n  \"kat_count\": {},\n{},\n{},\n{},\n  \"peak_hwm_kb\": {},\n  \"sizes\": {{\n    \"public_key_bytes\": {},\n    \"secret_key_bytes\": {},\n    \"ciphertext_bytes\": {},\n    \"shared_secret_bytes\": {}\n  }}\n}}",
        n,
        stats_block("keypair", &kp_times, &kp_rss),
        stats_block("enc", &enc_times, &enc_rss),
        stats_block("dec", &dec_times, &dec_rss),
        hwm_kb(),
        PUBLIC_KEY_BYTES,
        SECRET_KEY_BYTES,
        CIPHERTEXT_BYTES,
        SHARED_SECRET_BYTES,
    );
}

// ---------------------------------------------------------------------------
// Mode graph : exécution minimaliste pour callgrind
// ---------------------------------------------------------------------------

#[inline(never)]
fn do_keypair(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut ctx = symmetric::prng_init(seed, &[]);
    let mut ek = vec![0u8; PUBLIC_KEY_BYTES];
    let mut dk = vec![0u8; SECRET_KEY_BYTES];
    kem::crypto_kem_keypair(&mut ek, &mut dk, &mut ctx);
    (ek, dk)
}

#[inline(never)]
fn do_enc(ek: &[u8], seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut ctx = symmetric::prng_init(seed, &[]);
    let mut ct = vec![0u8; CIPHERTEXT_BYTES];
    let mut ss = vec![0u8; SHARED_SECRET_BYTES];
    kem::crypto_kem_enc(&mut ct, &mut ss, ek, &mut ctx);
    (ct, ss)
}

#[inline(never)]
fn do_dec(ct: &[u8], dk: &[u8]) -> Vec<u8> {
    let mut ss = vec![0u8; SHARED_SECRET_BYTES];
    kem::crypto_kem_dec(&mut ss, ct, dk);
    ss
}

fn run_graph(op: &str) {
    let seeds = parse_seeds(1);
    let seed = &seeds[0];

    match op {
        "keypair" => {
            do_keypair(seed);
        }
        "enc" => {
            let (ek, _dk) = do_keypair(seed);
            do_enc(&ek, seed);
        }
        "dec" => {
            let (ek, dk) = do_keypair(seed);
            let (ct, _ss) = do_enc(&ek, seed);
            do_dec(&ct, &dk);
        }
        _ => {
            // all
            let (ek, dk) = do_keypair(seed);
            let (ct, _ss) = do_enc(&ek, seed);
            do_dec(&ct, &dk);
        }
    }
}

// ---------------------------------------------------------------------------
// Mode raw : une ligne par KAT, même format que le C
// ---------------------------------------------------------------------------

fn run_raw(n: usize) {
    let seeds = parse_seeds(n);
    println!("keypair_ns enc_ns dec_ns keypair_rss_kb enc_rss_kb dec_rss_kb");
    for seed in &seeds {
        let mut ctx = symmetric::prng_init(seed, &[]);
        let mut ek_kem = vec![0u8; PUBLIC_KEY_BYTES];
        let mut dk_kem = vec![0u8; SECRET_KEY_BYTES];
        let mut ct = vec![0u8; CIPHERTEXT_BYTES];
        let mut ss = vec![0u8; SHARED_SECRET_BYTES];
        let mut ss_dec = vec![0u8; SHARED_SECRET_BYTES];

        let r0 = rss_kb();
        let t = Instant::now();
        kem::crypto_kem_keypair(&mut ek_kem, &mut dk_kem, &mut ctx);
        let kp_ns = t.elapsed().as_nanos() as u64;
        let kp_rss = rss_kb() - r0;

        let r0 = rss_kb();
        let t = Instant::now();
        kem::crypto_kem_enc(&mut ct, &mut ss, &ek_kem, &mut ctx);
        let enc_ns = t.elapsed().as_nanos() as u64;
        let enc_rss = rss_kb() - r0;

        let r0 = rss_kb();
        let t = Instant::now();
        kem::crypto_kem_dec(&mut ss_dec, &ct, &dk_kem);
        let dec_ns = t.elapsed().as_nanos() as u64;
        let dec_rss = rss_kb() - r0;

        println!("{} {} {} {} {} {}", kp_ns, enc_ns, dec_ns, kp_rss, enc_rss, dec_rss);
    }
    eprintln!("peak_hwm_kb {}", hwm_kb());
}

// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("time") => {
            let n = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100);
            run_timing(n);
        }
        Some("raw") => {
            let n = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100);
            run_raw(n);
        }
        Some("graph") => {
            let op = args.get(2).map(String::as_str).unwrap_or("all");
            run_graph(op);
        }
        _ => {
            // défaut : timing sur N KATs
            let n = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);
            run_timing(n);
        }
    }
}
