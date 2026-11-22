//! Does the running time of scalar multiplication depend on the scalar?
//!
//! Method from dudect (Reparaz, Balasch, Verbauwhede, "Dude, is my code
//! constant time?", DATE 2017): time many calls with inputs from two classes,
//! one fixed scalar and fresh random scalars, interleaved in random order so
//! drift affects both classes equally. Then Welch's t-test asks whether the
//! two timing distributions have different means. |t| > 4.5 is the usual
//! threshold for "leak detected".
//!
//! A large |t| proves a leak. A small |t| only means this test, on this
//! machine, with this many samples, found none.
//!
//!     cargo run --release --example timing [samples per routine]

use ed25519_rs::hazmat::EdwardsPoint;
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

/// Running mean and variance (Welford).
#[derive(Default, Clone, Copy)]
struct Stats {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Stats {
    fn push(&mut self, x: f64) {
        self.n += 1.0;
        let d = x - self.mean;
        self.mean += d / self.n;
        self.m2 += d * (x - self.mean);
    }
    fn var(&self) -> f64 {
        self.m2 / (self.n - 1.0)
    }
}

fn welch_t(a: &Stats, b: &Stats) -> f64 {
    (a.mean - b.mean) / (a.var() / a.n + b.var() / b.n).sqrt()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for c in out.chunks_exact_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        out
    }
}

fn percentile(sorted: &[u64], q: f64) -> u64 {
    sorted[((sorted.len() - 1) as f64 * q) as usize]
}

fn experiment(name: &str, n: usize, f: &dyn Fn(&[u8; 32]) -> EdwardsPoint) -> String {
    // Fixed class: a sparse scalar, eight 1 bits out of 256.
    let mut fixed = [0u8; 32];
    for i in (0..32).step_by(4) {
        fixed[i] = 1;
    }
    let mut rng = Rng(0x9e3779b97f4a7c15);
    // Draw classes and scalars up front so the generator is outside the timed region.
    let inputs: Vec<(usize, [u8; 32])> = (0..n)
        .map(|_| {
            let class = (rng.next() & 1) as usize;
            (class, if class == 0 { fixed } else { rng.bytes32() })
        })
        .collect();
    for (_, k) in inputs.iter().take(200) {
        black_box(f(black_box(k))); // warm-up
    }
    let mut samples = Vec::with_capacity(n);
    for (class, k) in &inputs {
        let t0 = Instant::now();
        black_box(f(black_box(k)));
        samples.push((*class, t0.elapsed().as_nanos() as u64));
    }

    // Crop at the 99th percentile of all samples: the slow tail is interrupts
    // and scheduling, not the code, and it would swamp the variance.
    let mut sorted: Vec<u64> = samples.iter().map(|s| s.1).collect();
    sorted.sort_unstable();
    let cut = percentile(&sorted, 0.99);
    let lo = percentile(&sorted, 0.001);

    let mut all = [Stats::default(); 2];
    let mut kept = [Stats::default(); 2];
    let mut trajectory = Vec::new();
    for (i, (class, t)) in samples.iter().enumerate() {
        all[*class].push(*t as f64);
        if *t <= cut {
            kept[*class].push(*t as f64);
        }
        if (i + 1) % (n / 100) == 0 {
            trajectory.push(format!("[{}, {:.3}]", i + 1, welch_t(&kept[0], &kept[1])));
        }
    }
    let t_all = welch_t(&all[0], &all[1]);
    let t_kept = welch_t(&kept[0], &kept[1]);

    // Histogram of kept samples, per class.
    const BINS: usize = 80;
    let width = ((cut - lo) as f64 / BINS as f64).max(1.0);
    let mut hist = [[0u32; BINS]; 2];
    for (class, t) in &samples {
        if *t >= lo && *t <= cut {
            let b = (((*t - lo) as f64 / width) as usize).min(BINS - 1);
            hist[*class][b] += 1;
        }
    }
    let fmt_hist = |h: &[u32; BINS]| {
        h.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mean_us = |s: &Stats| s.mean / 1000.0;
    println!(
        "{name:28} fixed {:8.2} µs  random {:8.2} µs  t = {:8.2} (cropped), {:8.2} (all)",
        mean_us(&kept[0]),
        mean_us(&kept[1]),
        t_kept,
        t_all
    );

    let mut j = String::new();
    write!(
        j,
        "{{\"name\": \"{name}\", \"samples\": {n}, \"cut_ns\": {cut}, \"low_ns\": {lo}, \"bin_width_ns\": {width:.3}, \
         \"mean_fixed_ns\": {:.1}, \"mean_random_ns\": {:.1}, \"kept\": [{}, {}], \
         \"t_cropped\": {t_kept:.3}, \"t_all\": {t_all:.3}, \"trajectory\": [{}], \
         \"hist_fixed\": [{}], \"hist_random\": [{}]}}",
        kept[0].mean,
        kept[1].mean,
        kept[0].n,
        kept[1].n,
        trajectory.join(", "),
        fmt_hist(&hist[0]),
        fmt_hist(&hist[1]),
    )
    .unwrap();
    j
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .map(|s| s.parse().unwrap())
        .unwrap_or(40_000);
    let b = EdwardsPoint::basepoint();
    let leaky = experiment("double-and-add (variable)", n, &|k| b.mul_vartime(k));
    let ct = experiment("4-bit window (constant)", n, &|k| EdwardsPoint::mul_base(k));
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .map(|l| l.split(':').nth(1).unwrap().trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    let json = format!("{{\"cpu\": \"{cpu}\", \"threshold\": 4.5, \"runs\": [{leaky}, {ct}]}}\n");
    std::fs::create_dir_all("docs").unwrap();
    std::fs::write("docs/timing.json", json).unwrap();
    println!("wrote docs/timing.json");
}
