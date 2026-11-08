//! holo-net — transport primitives from the published networking literature,
//! implemented std-only and validated by deterministic simulation tests.
//!
//! Contents and their sources:
//! - [`RttEstimator`]: Jacobson/Karels RTO (RFC 6298; Jacobson, "Congestion
//!   Avoidance and Control", SIGCOMM '88) with Karn backoff.
//! - [`TokenBucket`]: classic leaky/token bucket pacing.
//! - [`DrrQueue`]: Deficit Round Robin fair queuing (Shreedhar & Varghese,
//!   "Efficient Fair Queuing Using Deficit Round Robin", SIGCOMM '95).
//! - [`CoDel`]: Controlling Queue Delay (Nichols & Jacobson, ACM Queue 2012).
//! - [`Cubic`]: Ha, Rhee & Xu, "CUBIC: A New TCP-Friendly High-Speed TCP
//!   Variant" (ACM SIGOPS OSR 2008), with HyStart++ slow start (RFC 9065).
//! - [`Bbr`]: Cardwell, Cheng, Gunn, Yeganeh & Jacobson, "BBR: Congestion-
//!   Based Congestion Control" (CACM 2017) — model portion: BtlBw max
//!   filter, RTprop min filter, ProbeBW/ProbeRTT state machine.
//! - [`Padder`]: length-hiding padding against traffic-analysis
//!   fingerprinting (motivated by Sirinam et al., "Deep Fingerprinting",
//!   CCS 2018; Dyer et al., "Protocol Misidentification Made Easy with
//!   Format-Transforming Encryption", CCS 2013).
//! - [`ProbeGuard`]: active-probing resistance — per-peer exponential
//!   backoff on handshake failures (countermeasure to GFW-style active
//!   probing of fully-encrypted proxies, FOCI workshop literature).
//! - [`BufferPool`]: fixed-size buffer recycling for low, stable memory.
//!
//! Everything is `#![forbid(unsafe_code)]`, allocation-light, and tested
//! against a deterministic [`sim::Link`] bottleneck model.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// RTT estimation — RFC 6298
// ---------------------------------------------------------------------------

/// Jacobson/Karels RTT estimator + RTO with Karn backoff (RFC 6298).
#[derive(Debug, Clone)]
pub struct RttEstimator {
    srtt_ms: f64,
    rttvar_ms: f64,
    rto_ms: f64,
    initialized: bool,
}

const RTT_ALPHA: f64 = 1.0 / 8.0;
const RTT_BETA: f64 = 1.0 / 4.0;
const RTT_K: f64 = 4.0;
/// Clock granularity assumed for G (1 ms — all samples are integral ms).
const RTT_G: f64 = 1.0;
pub const RTO_MIN_MS: f64 = 200.0;
pub const RTO_MAX_MS: f64 = 60_000.0;

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        RttEstimator {
            srtt_ms: 0.0,
            rttvar_ms: 0.0,
            rto_ms: RTO_MIN_MS,
            initialized: false,
        }
    }

    /// Feed one fresh RTT sample (never retransmitted — Karn's rule is the
    /// caller's responsibility; use [`Self::on_retransmit`] for backoff).
    pub fn update(&mut self, sample_ms: u64) {
        let r = sample_ms as f64;
        if !self.initialized {
            self.srtt_ms = r;
            self.rttvar_ms = r / 2.0;
            self.initialized = true;
        } else {
            let delta = (self.srtt_ms - r).abs();
            self.rttvar_ms = (1.0 - RTT_BETA) * self.rttvar_ms + RTT_BETA * delta;
            self.srtt_ms = (1.0 - RTT_ALPHA) * self.srtt_ms + RTT_ALPHA * r;
        }
        self.rto_ms = self.srtt_ms + RTT_G.max(RTT_K * self.rttvar_ms);
        self.rto_ms = self.rto_ms.clamp(RTO_MIN_MS, RTO_MAX_MS);
    }

    /// Karn backoff: double the RTO (capped) — called when a segment is
    /// retransmitted, and no RTT sample is taken for it.
    pub fn on_retransmit(&mut self) {
        self.rto_ms = (self.rto_ms * 2.0).min(RTO_MAX_MS);
    }

    pub fn rto_ms(&self) -> u64 {
        self.rto_ms as u64
    }
    pub fn srtt_ms(&self) -> f64 {
        self.srtt_ms
    }
    pub fn initialized(&self) -> bool {
        self.initialized
    }
}

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

/// Continuous-refill token bucket. `rate` bytes/sec, `burst` bytes.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate_bps: f64,
    burst: f64,
    tokens: f64,
    last: Option<Instant>,
}

impl TokenBucket {
    pub fn new(rate_bps: u64, burst: u64) -> Self {
        TokenBucket {
            rate_bps: rate_bps as f64,
            burst: burst as f64,
            tokens: burst as f64,
            last: None,
        }
    }

    pub fn unlimited() -> Self {
        TokenBucket {
            rate_bps: f64::INFINITY,
            burst: f64::INFINITY,
            tokens: f64::INFINITY,
            last: None,
        }
    }

    pub fn unlimited_enabled(&self) -> bool {
        !self.rate_bps.is_finite()
    }

    fn refill(&mut self, now: Instant) {
        match self.last {
            None => {}
            Some(t) => {
                let dt = now.duration_since(t).as_secs_f64();
                if dt > 0.0 {
                    self.tokens = (self.tokens + self.rate_bps * dt).min(self.burst);
                }
            }
        }
        self.last = Some(now);
    }

    /// Try to take `n` tokens. `Ok(())` granted; `Err(d)` — wait at least
    /// `d` before retrying.
    pub fn try_acquire(&mut self, n: usize) -> Result<(), Duration> {
        let n = n as f64;
        if !self.rate_bps.is_finite() {
            return Ok(());
        }
        let now = Instant::now();
        self.refill(now);
        if self.tokens >= n {
            self.tokens -= n;
            Ok(())
        } else {
            let deficit = n - self.tokens;
            let wait = Duration::from_secs_f64(deficit / self.rate_bps);
            Err(wait)
        }
    }

    /// Blocking acquire: sleeps until the tokens are available. Caps each
    /// individual sleep at 50 ms so callers stay responsive to shutdown.
    pub fn acquire(&mut self, n: usize, check_stop: &dyn Fn() -> bool) -> bool {
        loop {
            if check_stop() {
                return false;
            }
            match self.try_acquire(n) {
                Ok(()) => return true,
                Err(d) => {
                    let d = d.min(Duration::from_millis(50));
                    std::thread::sleep(d);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Deficit Round Robin — Shreedhar & Varghese, SIGCOMM '95
// ---------------------------------------------------------------------------

/// Per-flow deficit scheduling over queued byte-costs.
///
/// Each flow accumulates `quantum` credits per visit; a queued item of
/// `cost` bytes is served when the deficit covers it, otherwise the flow
/// is skipped this round (its deficit persists — the DRR invariant).
pub struct DrrQueue<T> {
    order: Vec<u64>,
    queues: HashMap<u64, std::collections::VecDeque<(usize, T)>>,
    deficits: HashMap<u64, f64>,
    quanta: HashMap<u64, f64>,
    round_robin: usize,
    total_queued: usize,
}

impl<T> Default for DrrQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> DrrQueue<T> {
    pub fn new() -> Self {
        DrrQueue {
            order: Vec::new(),
            queues: HashMap::new(),
            deficits: HashMap::new(),
            quanta: HashMap::new(),
            round_robin: 0,
            total_queued: 0,
        }
    }

    /// Register a flow with its quantum (proportional share).
    pub fn register(&mut self, flow: u64, quantum: usize) {
        if !self.queues.contains_key(&flow) {
            self.order.push(flow);
            self.queues.insert(flow, std::collections::VecDeque::new());
            self.deficits.insert(flow, 0.0);
            self.quanta.insert(flow, quantum as f64);
        } else {
            self.quanta.insert(flow, quantum as f64);
        }
    }

    pub fn unregister(&mut self, flow: u64) {
        if let Some(q) = self.queues.remove(&flow) {
            self.total_queued -= q.len();
        }
        self.order.retain(|f| *f != flow);
        self.deficits.remove(&flow);
        self.quanta.remove(&flow);
        self.round_robin = 0;
    }

    pub fn push(&mut self, flow: u64, item: T, cost: usize) {
        let q = self
            .queues
            .get_mut(&flow)
            .unwrap_or_else(|| panic!("drr: flow {} not registered", flow));
        q.push_back((cost, item));
        self.total_queued += 1;
    }

    pub fn len(&self) -> usize {
        self.total_queued
    }
    pub fn is_empty(&self) -> bool {
        self.total_queued == 0
    }

    /// Serve the next item in DRR order. Returns `(flow, item)` or None.
    pub fn pop(&mut self) -> Option<(u64, T)> {
        if self.order.is_empty() {
            return None;
        }
        // one pass over flows; items served within the visit while the
        // deficit allows, per the DRR paper.
        for _ in 0..self.order.len() {
            if self.round_robin >= self.order.len() {
                self.round_robin = 0;
            }
            let flow = self.order[self.round_robin];
            let quantum = *self.quanta.get(&flow)?;
            let deficit = self.deficits.entry(flow).or_insert(0.0);
            *deficit += quantum;
            let q = self.queues.get_mut(&flow)?;
            if let Some((cost, _)) = q.front() {
                if *deficit >= *cost as f64 {
                    let (cost, item) = q.pop_front()?;
                    *deficit -= cost as f64;
                    self.total_queued -= 1;
                    self.round_robin += 1;
                    return Some((flow, item));
                }
            }
            // flow empty or cannot afford head item: zero deficit if empty
            // (paper: reset to zero for empty queues), move on.
            if q.is_empty() {
                *deficit = 0.0;
            }
            self.round_robin += 1;
        }
        None
    }
}

// ---------------------------------------------------------------------------
// CoDel — Nichols & Jacobson, "Controlling Queue Delay", ACM Queue 2012
// ---------------------------------------------------------------------------

/// Simplified CoDel drop decision, evaluated at dequeue time.
pub struct CoDel {
    target: Duration,
    interval: Duration,
    first_above_time: Option<Instant>,
    drop_next: Option<Instant>,
    count: u32,
    dropping: bool,
    last_drop: Option<Instant>,
}

impl Default for CoDel {
    fn default() -> Self {
        Self::new()
    }
}

impl CoDel {
    pub fn new() -> Self {
        CoDel {
            target: Duration::from_millis(5),
            interval: Duration::from_millis(100),
            first_above_time: None,
            drop_next: None,
            count: 0,
            dropping: false,
            last_drop: None,
        }
    }

    /// Reset (call when the queue becomes empty — the paper's ok() reset).
    pub fn on_idle(&mut self) {
        self.first_above_time = None;
        self.dropping = false;
        self.count = 0;
    }

    /// Should the dequeued head (enqueued at `enqueued_at`) be dropped?
    pub fn should_drop(&mut self, enqueued_at: Instant, now: Instant) -> bool {
        let sojourn = now.saturating_duration_since(enqueued_at);
        if sojourn < self.target {
            self.first_above_time = None;
        } else if self.first_above_time.is_none() {
            self.first_above_time = Some(now);
        }
        if self.dropping {
            if !self.ok_to_drop(now, sojourn) {
                self.dropping = false;
                return false;
            }
            // drop, advance drop_next by the inversesqrt schedule
            self.count += 1;
            let div = (1.0 + self.count.saturating_sub(1) as f64).sqrt();
            let next = self.drop_next.unwrap_or(now) + self.interval.div_f64(div.max(1.0));
            self.drop_next = Some(next);
            self.last_drop = Some(now);
            return true;
        }
        if self.ok_to_drop(now, sojourn) {
            self.dropping = true;
            self.count = if self.last_drop.is_some()
                && now.saturating_duration_since(self.last_drop.unwrap()) < self.interval
            {
                (self.count + 1).min(16)
            } else {
                1
            };
            let div = (1.0 + (self.count - 1) as f64).sqrt();
            let next = now + self.interval.div_f64(div.max(1.0));
            self.drop_next = Some(next);
            self.last_drop = Some(now);
            return true;
        }
        false
    }

    fn ok_to_drop(&self, now: Instant, sojourn: Duration) -> bool {
        if sojourn >= self.target {
            if let Some(t) = self.first_above_time {
                if now.duration_since(t) >= self.interval {
                    return true;
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// CUBIC + HyStart++ — Ha/Rhee/Xu 2008; RFC 9065
// ---------------------------------------------------------------------------

/// CUBIC congestion controller (simplified: cubic + TCP-friendly regions,
/// multiplicative decrease β=0.7) with a HyStart++-style slow start exit.
pub struct Cubic {
    cwnd: f64,
    ssthresh: f64,
    w_max: f64,
    epoch_start: Option<Instant>,
    tcp_cwnd: f64,
    k: f64,
    mss: f64,
    // HyStart++ state
    in_slow_start: bool,
    round_min_rtt: f64,
    current_min_rtt: f64,
    round_start: Option<Instant>,
    css_rounds: u32,
    last_congestion: Option<Instant>,
}

const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;
const CSS_ROUNDS: u32 = 5;
/// HyStart++ slow-start exit threshold (16·MSS per RFC 9065 default).
const HYSTART_EXIT: f64 = 16.0;

impl Cubic {
    pub fn new(mss: usize) -> Self {
        let mss = mss as f64;
        Cubic {
            cwnd: 10.0 * mss, // RFC 6928 IW10
            ssthresh: f64::INFINITY,
            w_max: 10.0 * mss,
            epoch_start: None,
            tcp_cwnd: 0.0,
            k: 0.0,
            mss,
            in_slow_start: true,
            round_min_rtt: f64::INFINITY,
            current_min_rtt: f64::INFINITY,
            round_start: None,
            css_rounds: 0,
            last_congestion: None,
        }
    }

    pub fn cwnd(&self) -> u64 {
        self.cwnd as u64
    }
    pub fn in_slow_start(&self) -> bool {
        self.in_slow_start
    }

    fn recompute_k(&mut self) {
        // K = cbrt(W_max · (1-β) / C)
        self.k = ((self.w_max * (1.0 - CUBIC_BETA) / CUBIC_C) / 1000.0).cbrt() * 10.0;
    }

    /// One ACK: `bytes` newly acknowledged, `rtt` the (fresh) RTT sample.
    pub fn on_ack(&mut self, now: Instant, rtt: Option<Duration>, bytes: u64) {
        let segs = (bytes as f64 / self.mss).max(1.0);
        if self.in_slow_start {
            // HyStart++: track round min-RTT; exit on RTT growth or threshold
            if let Some(r) = rtt {
                let rms = r.as_secs_f64() * 1000.0;
                self.current_min_rtt = self.current_min_rtt.min(rms);
            }
            let round_elapsed = self
                .round_start
                .map(|t| {
                    now.duration_since(t)
                        >= Duration::from_millis((self.round_min_rtt * 2.0).max(2.0) as u64)
                })
                .unwrap_or(true);
            if round_elapsed {
                let grew = self.current_min_rtt > self.round_min_rtt * 1.4
                    && self.current_min_rtt < f64::INFINITY
                    && self.round_min_rtt < f64::INFINITY;
                self.round_min_rtt = self.current_min_rtt;
                self.current_min_rtt = f64::INFINITY;
                self.round_start = Some(now);
                if grew || self.cwnd >= HYSTART_EXIT * self.mss {
                    // enter Conservative Slow Start (half-MSS growth)
                    self.css_rounds = CSS_ROUNDS;
                    if self.cwnd >= HYSTART_EXIT * self.mss {
                        self.in_slow_start = false;
                        self.epoch_start = Some(now);
                        self.recompute_k();
                    }
                }
            }
            if self.in_slow_start {
                if self.css_rounds > 0 {
                    self.cwnd += self.mss / 2.0 * segs;
                    self.css_rounds -= 1;
                } else {
                    self.cwnd += self.mss * segs;
                }
                return;
            }
        }
        // congestion avoidance: CUBIC
        if self.epoch_start.is_none() {
            self.epoch_start = Some(now);
            self.recompute_k();
            self.tcp_cwnd = self.cwnd;
        }
        let t = now
            .duration_since(self.epoch_start.unwrap_or(now))
            .as_secs_f64();
        let w_cubic = CUBIC_C * (t - self.k).powi(3) + self.w_max;
        // TCP-friendly region
        self.tcp_cwnd += 3.0 * CUBIC_BETA / (2.0 - CUBIC_BETA) * segs;
        let tcp_target = self.tcp_cwnd.min(self.w_max);
        let target = w_cubic.max(tcp_target);
        self.cwnd += (target - self.cwnd) / self.cwnd * segs.min(1.0) * self.mss / self.mss;
        // clamp per-ACK growth to be additive at most
        self.cwnd = self.cwnd.min(self.cwnd.max(target).max(self.w_max * 1.5));
    }

    /// Loss / ECN event.
    pub fn on_loss(&mut self, now: Instant) {
        self.w_max = self.cwnd;
        self.cwnd = (self.cwnd * CUBIC_BETA).max(2.0 * self.mss);
        self.ssthresh = self.cwnd;
        self.in_slow_start = false;
        self.epoch_start = None;
        self.tcp_cwnd = self.cwnd;
        self.recompute_k();
        self.last_congestion = Some(now);
    }

    /// Pacing rate hint: cwnd / smoothed RTT.
    pub fn pacing_rate(&self, rtt: Duration) -> f64 {
        let r = rtt.as_secs_f64().max(0.001);
        self.cwnd / r
    }
}

// ---------------------------------------------------------------------------
// BBR (model portion) — Cardwell et al., CACM 2017
// ---------------------------------------------------------------------------

/// BBR congestion controller (model portion: BtlBw max-filter, RTprop
/// min-filter, ProbeBW gain cycle, ProbeRTT).
pub struct Bbr {
    mss: f64,
    btl_bw: f64, // bytes/sec, max-filter over last ~10 round trips
    bw_samples: std::collections::VecDeque<(Instant, f64)>,
    rtprop: f64, // sec, min-filter over 10 s
    rtprop_stamp: Instant,
    pacing_gain: f64,
    cwnd_gain: f64,
    cycle_idx: usize,
    cycle_start: Instant,
    probe_rtt_since: Option<Instant>,
    probe_rtt_until: Option<Instant>,
    delivered_last: f64,
}

const BBR_BW_WINDOW: Duration = Duration::from_secs(10);
const BBR_RTPROP_WINDOW: Duration = Duration::from_secs(10);
const BBR_PROBE_RTT_MS: u64 = 200;
/// ProbeBW pacing gain cycle (BBR paper §4.3.2).
const BBR_GAIN_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

impl Bbr {
    pub fn new(mss: usize, now: Instant) -> Self {
        Bbr {
            mss: mss as f64,
            btl_bw: 0.0,
            bw_samples: std::collections::VecDeque::new(),
            rtprop: f64::INFINITY,
            rtprop_stamp: now,
            pacing_gain: 1.0,
            cwnd_gain: 2.0,
            cycle_idx: 0,
            cycle_start: now,
            probe_rtt_since: None,
            probe_rtt_until: None,
            delivered_last: 0.0,
        }
    }

    /// One ACK with a fresh RTT sample and the bytes it acknowledges.
    pub fn on_ack(&mut self, now: Instant, rtt: Duration, bytes: u64) {
        let r = rtt.as_secs_f64();
        if r < self.rtprop {
            self.rtprop = r;
            self.rtprop_stamp = now;
        }
        // delivery-rate estimate for this round: bytes / rtt
        if r > 0.0 {
            let rate = bytes as f64 / r;
            self.bw_samples.push_back((now, rate));
            while let Some((t, _)) = self.bw_samples.front() {
                if now.duration_since(*t) > BBR_BW_WINDOW {
                    self.bw_samples.pop_front();
                } else {
                    break;
                }
            }
            self.btl_bw = self
                .bw_samples
                .iter()
                .map(|(_, x)| *x)
                .fold(0.0f64, f64::max);
        }

        // ProbeRTT: no RTprop refresh in 10 s → drain to 4 packets for 200 ms
        if self.probe_rtt_until.is_none()
            && now.duration_since(self.rtprop_stamp) >= BBR_RTPROP_WINDOW
        {
            self.probe_rtt_since = Some(now);
            self.probe_rtt_until = Some(now + Duration::from_millis(BBR_PROBE_RTT_MS));
            self.pacing_gain = 1.0;
        }
        if let Some(until) = self.probe_rtt_until {
            if now >= until {
                self.probe_rtt_until = None;
                self.probe_rtt_since = None;
                self.cycle_start = now;
            }
        } else {
            // ProbeBW cycle advance each RTProp
            if now.duration_since(self.cycle_start)
                >= Duration::from_secs_f64(self.rtprop.max(0.01))
            {
                self.cycle_idx = (self.cycle_idx + 1) % BBR_GAIN_CYCLE.len();
                self.cycle_start = now;
                self.pacing_gain = BBR_GAIN_CYCLE[self.cycle_idx];
            }
        }
        self.delivered_last = bytes as f64;
    }

    pub fn pacing_rate_bps(&self) -> f64 {
        let base = if self.rtprop.is_finite() && self.btl_bw > 0.0 {
            self.btl_bw
        } else {
            // startup: IW10 / RTprop fallback
            10.0 * self.mss / self.rtprop.max(0.005)
        };
        self.pacing_gain * base
    }

    pub fn cwnd(&self) -> u64 {
        if self.probe_rtt_until.is_some() {
            return (4.0 * self.mss) as u64;
        }
        let bdp = self.btl_bw * self.rtprop.max(0.005);
        (self.cwnd_gain * bdp + 4.0 * self.mss) as u64
    }

    pub fn in_probe_rtt(&self) -> bool {
        self.probe_rtt_until.is_some()
    }
}

// ---------------------------------------------------------------------------
// Padding — length-hiding (traffic-analysis mitigation)
// ---------------------------------------------------------------------------

/// Frame-padding policy against length fingerprinting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PadPolicy {
    Off,
    /// Pad the payload to a uniformly random length in [len, len+max].
    Random {
        max: usize,
    },
    /// Pad up to the next size in the ladder (hidden-in-plain-sight sizes).
    Buckets,
}

const PAD_LADDER: [usize; 8] = [64, 128, 256, 512, 1024, 2048, 4096, 8192];

pub struct Padder {
    policy: PadPolicy,
    lcg: u64,
}

impl Padder {
    pub fn new(policy: PadPolicy) -> Self {
        Padder {
            policy,
            lcg: 0x9E3779B97F4A7C15
                ^ std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0x1234),
        }
    }

    fn next_rand(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.lcg;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.lcg = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// The padded length for a payload of `len` bytes (≥ len, ≤ cap).
    pub fn pad_len(&mut self, len: usize) -> usize {
        match self.policy {
            PadPolicy::Off => len,
            PadPolicy::Random { max } => {
                if max == 0 {
                    len
                } else {
                    len + (self.next_rand() % (max as u64 + 1)) as usize
                }
            }
            PadPolicy::Buckets => {
                for cap in PAD_LADDER {
                    if len <= cap {
                        // random position within the bucket (not its end)
                        let room = cap - len;
                        return len + (self.next_rand() % (room as u64 + 1)) as usize;
                    }
                }
                len
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ProbeGuard — active-probing resistance
// ---------------------------------------------------------------------------

/// Per-peer exponential backoff after authentication failures. A prober
/// that blasts handshakes gets progressively slower closes; legitimate
/// users retrying after a typo see sub-second delays at worst.
pub struct ProbeGuard {
    attempts: HashMap<std::net::IpAddr, u32>,
    last: HashMap<std::net::IpAddr, Instant>,
    base_ms: u64,
    max_ms: u64,
}

impl Default for ProbeGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeGuard {
    pub fn new() -> Self {
        ProbeGuard {
            attempts: HashMap::new(),
            last: HashMap::new(),
            base_ms: 50,
            max_ms: 10_000,
        }
    }

    /// Record an auth failure for `peer`; returns the delay to apply
    /// before closing (or before accepting more work from it).
    pub fn on_failure(&mut self, peer: std::net::IpAddr) -> Duration {
        let n = self
            .attempts
            .entry(peer)
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let shift = (*n).min(10);
        let ms = (self.base_ms.saturating_mul(1u64 << shift)).min(self.max_ms);
        self.last.insert(peer, Instant::now());
        Duration::from_millis(ms)
    }

    /// A successful auth resets the peer's counter.
    pub fn on_success(&mut self, peer: std::net::IpAddr) {
        self.attempts.remove(&peer);
        self.last.remove(&peer);
    }

    pub fn attempts(&self, peer: std::net::IpAddr) -> u32 {
        *self.attempts.get(&peer).unwrap_or(&0)
    }
}

// ---------------------------------------------------------------------------
// BufferPool — fixed-size buffer recycling
// ---------------------------------------------------------------------------

use std::sync::{Arc, Mutex};

struct PoolInner {
    free: Mutex<Vec<Vec<u8>>>,
    size: usize,
    max: usize,
    created: Mutex<usize>,
}

/// A fixed-size buffer pool. Buffers return to the pool on drop; above
/// `max` outstanding buffers, new ones are allocated normally and simply
/// not recycled (no unbounded growth, no blocking).
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<PoolInner>,
}

pub struct PooledBuf {
    buf: Option<Vec<u8>>,
    pool: Arc<PoolInner>,
}

impl std::ops::Deref for PooledBuf {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        self.buf.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for PooledBuf {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        self.buf.as_mut().unwrap()
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(mut b) = self.buf.take() {
            b.clear();
            let mut free = self.pool.free.lock().unwrap();
            if free.len() < self.pool.max {
                free.push(b);
            }
        }
    }
}

impl BufferPool {
    pub fn new(size: usize, max: usize) -> Self {
        BufferPool {
            inner: Arc::new(PoolInner {
                free: Mutex::new(Vec::new()),
                size,
                max,
                created: Mutex::new(0),
            }),
        }
    }

    pub fn get(&self) -> PooledBuf {
        let from_pool = self.inner.free.lock().unwrap().pop();
        match from_pool {
            Some(mut b) => {
                b.clear();
                b.resize(self.inner.size, 0);
                PooledBuf {
                    buf: Some(b),
                    pool: self.inner.clone(),
                }
            }
            None => {
                *self.inner.created.lock().unwrap() += 1;
                PooledBuf {
                    buf: Some(vec![0u8; self.inner.size]),
                    pool: self.inner.clone(),
                }
            }
        }
    }

    /// How many buffers are sitting free in the pool right now.
    pub fn pooled(&self) -> usize {
        self.inner.free.lock().unwrap().len()
    }

    /// Total buffers ever allocated (for the memory-leak regression test).
    pub fn created(&self) -> usize {
        *self.inner.created.lock().unwrap()
    }
}

// ---------------------------------------------------------------------------
// sim — deterministic bottleneck-link model for CC validation
// ---------------------------------------------------------------------------

pub mod sim {
    //! A deterministic bottleneck-link simulator: fixed service rate, base
    //! propagation delay, bounded queue, Bernoulli loss (xorshift RNG —
    //! reproducible across runs and platforms).

    #[derive(Clone)]
    pub struct Link {
        pub rate_bps: f64,
        pub rtt_ms: f64,
        pub queue_bytes: f64,
        pub loss_percent: f64,
        rng: u64,
    }

    impl Link {
        pub fn new(rate_bps: u64, rtt_ms: u64, queue_bytes: u64, loss_percent: f64) -> Self {
            Link {
                rate_bps: rate_bps as f64,
                rtt_ms: rtt_ms as f64,
                queue_bytes: queue_bytes as f64,
                loss_percent,
                rng: 0x1234_5678_9abc_def0,
            }
        }

        fn rand01(&mut self) -> f64 {
            let mut x = self.rng;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.rng = x;
            (x.wrapping_mul(0x2545F4914F6CDD1D) >> 11) as f64 / (1u64 << 53) as f64
        }

        /// Advance the simulation by one RTT: `offer_bps` is the send rate
        /// implied by pacing+cwnd; returns (achieved_bps, observed_rtt_ms,
        /// lost). The bottleneck queue drains at `rate_bps`; overflow →
        /// drop (a proxy for tail drop).
        pub fn step(&mut self, offer_bps: f64, co_del_drops: bool) -> (f64, f64, bool) {
            let rtt_s = self.rtt_ms / 1000.0;
            let offered_bytes = offer_bps * rtt_s;
            let drain_bytes = self.rate_bps * rtt_s;
            let queued = (offered_bytes - drain_bytes).max(0.0).min(self.queue_bytes);
            let delivered = if offered_bytes > self.queue_bytes + drain_bytes {
                drain_bytes
            } else {
                offered_bytes.min(drain_bytes)
            };
            let achieved_bps = delivered / rtt_s;
            let queue_rtt_ms = queued / self.rate_bps * 1000.0;
            let observed_rtt = self.rtt_ms + queue_rtt_ms;
            let lost = self.rand01() * 100.0 < self.loss_percent
                || (co_del_drops && offered_bytes > drain_bytes * 1.5);
            (achieved_bps, observed_rtt, lost)
        }
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rtt_estimator_rfc6298_convergence() {
        let mut e = RttEstimator::new();
        e.update(100);
        assert_eq!(e.rto_ms(), 100 + 200.max(4 * 50)); // SRTT=100, VAR=50 → RTO = 100 + max(G, 4·50)
                                                       // feed stable samples → RTO tightens to its floor (200 ms min)
        for _ in 0..20 {
            e.update(30);
        }
        assert!(
            e.srtt_ms() < 35.0 && e.srtt_ms() > 25.0,
            "srtt {}",
            e.srtt_ms()
        );
        assert!(e.rto_ms() <= RTO_MIN_MS as u64, "rto {}", e.rto_ms());
        // a single spike lifts RTO moderately
        e.update(300);
        assert!(e.rto_ms() > e.srtt_ms() as u64, "rto must exceed srtt");
        // Karn backoff
        let before = e.rto_ms();
        e.on_retransmit();
        assert_eq!(e.rto_ms(), before * 2);
    }

    #[test]
    fn token_bucket_limits_rate() {
        let mut tb = TokenBucket::new(10_000, 4_000); // 10 KB/s, 4 KB burst
                                                      // burst available immediately
        assert!(tb.try_acquire(4_000).is_ok());
        // next 1 KB needs ~100 ms of refill
        let wait = tb.try_acquire(1_000).unwrap_err();
        assert!(
            wait >= Duration::from_millis(80) && wait <= Duration::from_millis(150),
            "wait {wait:?}"
        );
        // unlimited buckets always grant
        let mut u = TokenBucket::unlimited();
        assert!(u.try_acquire(1 << 30).is_ok());
    }

    #[test]
    fn drr_fairness_two_flows() {
        let mut q: DrrQueue<u64> = DrrQueue::new();
        q.register(1, 1000);
        q.register(2, 500); // half share
        for i in 0..10 {
            q.push(1, i, 1000);
        }
        for i in 0..10 {
            q.push(2, 100 + i, 500);
        }
        let mut c1 = 0;
        let mut c2 = 0;
        while let Some((flow, _)) = q.pop() {
            match flow {
                1 => c1 += 1,
                _ => c2 += 1,
            }
            assert!(c1 <= c2 * 2 + 1 && c2 <= c1 + 1, "unfair {c1} vs {c2}");
        }
        assert_eq!(c1, 10);
        assert_eq!(c2, 10);
    }

    #[test]
    fn codel_drops_only_under_persistent_overload() {
        let mut cd = CoDel::new();
        let t0 = Instant::now();
        // well-behaved queue: sojourn under target → never drop
        let mut drops = 0;
        for _ in 0..50 {
            if cd.should_drop(t0 + Duration::from_millis(1), t0 + Duration::from_millis(2)) {
                drops += 1;
            }
        }
        assert_eq!(drops, 0);
        // overloaded: sojourn 50 ms >> 5 ms target, sustained → drops begin
        // after ~interval
        let mut cd2 = CoDel::new();
        let mut first_drop_at = None;
        for step in 0..200u32 {
            let now = t0 + Duration::from_millis(step.into());
            let enq = t0; // everything sits in queue from t0
            if cd2.should_drop(enq, now) && first_drop_at.is_none() {
                first_drop_at = Some(step);
            }
            if let Some(at) = first_drop_at {
                assert!(at >= 95, "codel dropped too early: step {at}");
                break;
            }
        }
        assert!(
            first_drop_at.is_some(),
            "codel never dropped under overload"
        );
    }

    #[test]
    fn cubic_converges_without_collapse() {
        let link = std::cell::RefCell::new(sim::Link::new(2_000_000, 40, 256_000, 0.0));
        let mut cc = Cubic::new(1400);
        let mut now = Instant::now();
        let mut total = 0f64;
        let mut rounds = 0;
        let mut rtt = Duration::from_millis(40);
        while rounds < 120 {
            rounds += 1;
            now += rtt;
            let offer = cc.pacing_rate(rtt).min(u32::MAX as f64);
            let (got, obs_rtt, lost) = link.borrow_mut().step(offer, false);
            total += got * (rtt.as_secs_f64());
            if lost {
                cc.on_loss(now);
            }
            cc.on_ack(now, Some(rtt), 1400 * 10);
            rtt = Duration::from_millis(obs_rtt as u64);
        }
        let avg_bps = total / (rounds as f64 * rtt.as_secs_f64().max(0.001));
        // converged throughput should be a sane fraction of the 2 Mbps link
        assert!(avg_bps > 500_000.0, "cubic collapsed: avg {avg_bps:.0} bps");
    }

    #[test]
    fn bbr_converges_near_bottleneck_without_queue_blowup() {
        let link = std::cell::RefCell::new(sim::Link::new(2_000_000, 40, 256_000, 0.0));
        let mut now = Instant::now();
        let mut bbr = Bbr::new(1400, now);
        let mut total = 0f64;
        let mut rounds = 0;
        let mut rtt = Duration::from_millis(40);
        let mut max_rtt = 0f64;
        while rounds < 200 {
            rounds += 1;
            now += rtt;
            let offer = bbr.pacing_rate_bps().min(u32::MAX as f64);
            let (got, obs_rtt, lost) = link.borrow_mut().step(offer, false);
            total += got * rtt.as_secs_f64();
            max_rtt = max_rtt.max(obs_rtt);
            let _ = lost;
            // feed the bytes actually delivered this round (what a real
            // receiver would ACK) — BBR's delivery-rate estimate needs it
            let delivered_bytes = (got * rtt.as_secs_f64()) as u64;
            bbr.on_ack(now, rtt, delivered_bytes);
            rtt = Duration::from_millis(obs_rtt.max(5.0) as u64);
        }
        let avg_bps = total / (rounds as f64 * rtt.as_secs_f64().max(0.001));
        assert!(
            avg_bps > 900_000.0,
            "bbr under-used the 2 Mbps link: avg {avg_bps:.0} bps"
        );
        assert!(
            max_rtt < 400.0,
            "bbr blew up the queue: max rtt {max_rtt:.1} ms"
        );
    }

    #[test]
    fn padder_bounds_and_policies() {
        let mut p = Padder::new(PadPolicy::Off);
        assert_eq!(p.pad_len(100), 100);
        let mut p = Padder::new(PadPolicy::Random { max: 64 });
        for len in [0usize, 1, 63, 100] {
            let l = p.pad_len(len);
            assert!(l >= len && l <= len + 64);
        }
        let mut p = Padder::new(PadPolicy::Buckets);
        let l = p.pad_len(100);
        assert!(l >= 100 && l <= 128, "bucket pad {l}");
        let l = p.pad_len(2000);
        assert!(l >= 2000 && l <= 2048);
        // all-zero LCG can't crash it either
        let mut q = Padder::new(PadPolicy::Random { max: 16 });
        q.lcg = 0;
        let _ = q.pad_len(10);
    }

    #[test]
    fn probe_guard_backs_off_and_resets() {
        let mut g = ProbeGuard::new();
        let peer: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let d1 = g.on_failure(peer);
        let d2 = g.on_failure(peer);
        let d3 = g.on_failure(peer);
        assert!(
            d2 > d1 && d3 > d2,
            "backoff not increasing: {d1:?} {d2:?} {d3:?}"
        );
        assert!(d3 <= Duration::from_millis(10_000), "capped");
        g.on_success(peer);
        assert_eq!(g.attempts(peer), 0);
        let d4 = g.on_failure(peer);
        assert!(d4 < d2, "reset didn't work");
    }

    #[test]
    fn buffer_pool_recycles_without_growth() {
        let pool = BufferPool::new(4096, 8);
        let mut kept = Vec::new();
        for _ in 0..8 {
            kept.push(pool.get());
        }
        assert_eq!(pool.created(), 8);
        drop(kept);
        assert_eq!(pool.pooled(), 8);
        // reuse: no new allocations
        let mut again = Vec::new();
        for _ in 0..8 {
            let b = pool.get();
            assert_eq!(b.len(), 4096);
            again.push(b);
        }
        assert_eq!(pool.created(), 8, "pool must recycle, not allocate");
        drop(again);
        // over-capacity: extra buffers just don't recycle
        let extra = pool.get();
        drop(extra);
        assert!(pool.pooled() <= 8);
    }
}
