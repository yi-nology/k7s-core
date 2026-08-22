//! Parsing node-exporter's metrics, and turning successive scrapes into plottable
//! samples (B27).
//!
//! Why scrape node-exporter directly rather than ask Prometheus: Prometheus is
//! the better source when it works — it has history and computes rates properly —
//! but it only has node metrics if it's actually scraping the exporters, and a
//! cluster whose scrape targets have drifted (murphy-yi's point at a node IP that no
//! longer exists) has none at all. Reading the exporters ourselves works wherever
//! the pods run, at the cost of only having data from when you started looking.
//!
//! Most of what an exporter returns is not wanted: murphy-yi's serves ~411KB, of
//! which we keep six families. Parsing is therefore a single filtered pass rather
//! than a general-purpose Prometheus text parser.
//!
//! The counters need care. `node_cpu_seconds_total` and the network byte counters
//! only mean something as a *rate*, which needs two samples; and a counter can go
//! backwards when the exporter restarts or the node reboots, which naively
//! produces an enormous negative rate. Both are handled in [`Sampler::push`].

use serde::Serialize;
use std::collections::BTreeMap;

/// A node's metrics at one instant, with rates already computed. Emitted to the
/// frontend, which only plots it.
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NodeSample {
    /// Epoch milliseconds — the x axis.
    pub ts: i64,
    /// Busy CPU, 0–100, across all cores.
    pub cpu_percent: f64,
    pub mem_used_bytes: f64,
    pub mem_total_bytes: f64,
    /// Bytes/second, summed over physical interfaces.
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    /// Per-mount usage. Slow-moving, so the UI shows it as a current bar chart
    /// rather than a series.
    pub filesystems: Vec<Filesystem>,
}

/// One mounted filesystem worth showing.
#[derive(Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Filesystem {
    pub mountpoint: String,
    pub used_bytes: f64,
    pub size_bytes: f64,
}

/// The values of one scrape, before rates.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RawSample {
    pub ts: i64,
    /// CPU seconds per mode, summed across cores.
    pub cpu_seconds: BTreeMap<String, f64>,
    pub mem_total: f64,
    pub mem_available: f64,
    /// Cumulative received/transmitted bytes over physical interfaces.
    pub net_rx: f64,
    pub net_tx: f64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    /// mountpoint → (size, avail)
    pub filesystems: BTreeMap<String, (f64, f64)>,
}

/// Interface name prefixes that aren't a real NIC.
///
/// murphy-yi reports 45 network devices, nearly all of them one veth per pod. Summing
/// those would double-count every packet — traffic to a pod crosses both its veth
/// and the physical NIC — and the total would jump around as pods come and go.
const VIRTUAL_IFACE_PREFIXES: &[&str] = &[
    "lo",
    "veth",
    "docker",
    "br-",
    "cni",
    "flannel",
    "kube-ipvs",
    "tunl",
    "dummy",
    "virbr",
    "tap",
    "vxlan",
    "nodelocaldns",
    "cali",
    "wg",
];

/// Filesystem types that aren't real storage — mostly RAM pretending to be a disk.
const VIRTUAL_FSTYPES: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "ramfs",
    "overlay",
    "squashfs",
    "iso9660",
    "autofs",
    "binfmt_misc",
    "cgroup",
    "cgroup2",
    "proc",
    "sysfs",
    "debugfs",
    "tracefs",
    "fuse.portal",
    "nsfs",
];

/// True for an interface whose bytes should be counted.
fn is_physical_iface(dev: &str) -> bool {
    !VIRTUAL_IFACE_PREFIXES.iter().any(|p| dev.starts_with(p))
}

/// Mount points that are kernel interfaces or churn, not storage.
///
/// The fstype blocklist doesn't catch these: murphy-yi mounts nfsd under /proc and
/// efivars under /sys, both of which report a real fstype and zero bytes, and
/// kubelet remounts the same devices once per pod.
const NON_STORAGE_MOUNT_PREFIXES: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/host/proc",
    "/host/sys",
];

/// True for a filesystem worth showing.
fn is_real_filesystem(fstype: &str, mountpoint: &str) -> bool {
    if VIRTUAL_FSTYPES.contains(&fstype) {
        return false;
    }
    !NON_STORAGE_MOUNT_PREFIXES
        .iter()
        .any(|p| mountpoint.starts_with(p))
}

/// Value of one label from a metric line's `{...}` section.
fn label(labels: &str, key: &str) -> Option<String> {
    // Labels are `k="v",k2="v2"`; values are quoted and may contain commas, so
    // this walks to the key rather than splitting on commas.
    let needle = format!("{key}=\"");
    let start = labels.find(&needle)? + needle.len();
    let rest = &labels[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Split `name{labels} value` into its parts.
fn split_line(line: &str) -> Option<(&str, &str, f64)> {
    // Exposition format puts the value after the last space.
    let (head, value) = line.rsplit_once(' ')?;
    // "+Inf"/"NaN" are legal and useless here.
    let value: f64 = value.parse().ok()?;
    if !value.is_finite() {
        return None;
    }
    match head.split_once('{') {
        Some((name, rest)) => Some((name, rest.trim_end_matches('}'), value)),
        None => Some((head, "", value)),
    }
}

/// Parse the families we plot out of a node-exporter scrape.
pub fn parse(text: &str, ts: i64) -> RawSample {
    let mut s = RawSample {
        ts,
        ..Default::default()
    };
    // size/avail arrive on separate lines, so filesystems are assembled as we go.
    let mut fs_size: BTreeMap<String, f64> = BTreeMap::new();
    let mut fs_avail: BTreeMap<String, f64> = BTreeMap::new();

    for line in text.lines() {
        // Comments are # HELP / # TYPE.
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some((name, labels, value)) = split_line(line) else {
            continue;
        };

        match name {
            "node_cpu_seconds_total" => {
                if let Some(mode) = label(labels, "mode") {
                    *s.cpu_seconds.entry(mode).or_insert(0.0) += value;
                }
            }
            "node_memory_MemTotal_bytes" => s.mem_total = value,
            "node_memory_MemAvailable_bytes" => s.mem_available = value,
            "node_network_receive_bytes_total" => {
                if label(labels, "device").is_some_and(|d| is_physical_iface(&d)) {
                    s.net_rx += value;
                }
            }
            "node_network_transmit_bytes_total" => {
                if label(labels, "device").is_some_and(|d| is_physical_iface(&d)) {
                    s.net_tx += value;
                }
            }
            "node_load1" => s.load1 = value,
            "node_load5" => s.load5 = value,
            "node_load15" => s.load15 = value,
            "node_filesystem_size_bytes" | "node_filesystem_avail_bytes" => {
                let (Some(mp), Some(fst)) = (label(labels, "mountpoint"), label(labels, "fstype"))
                else {
                    continue;
                };
                if !is_real_filesystem(&fst, &mp) {
                    continue;
                }
                if name.ends_with("size_bytes") {
                    fs_size.insert(mp, value);
                } else {
                    fs_avail.insert(mp, value);
                }
            }
            _ => {}
        }
    }

    for (mp, size) in fs_size {
        // A zero-byte filesystem has nothing to plot and would render as an empty
        // bar with a divide-by-zero percentage.
        if size <= 0.0 {
            continue;
        }
        if let Some(avail) = fs_avail.get(&mp) {
            s.filesystems.insert(mp, (size, *avail));
        }
    }
    s
}

/// Turns scrapes into samples, holding the previous scrape so counters can be
/// differenced.
#[derive(Default)]
pub struct Sampler {
    prev: Option<RawSample>,
}

impl Sampler {
    /// Feed a scrape. Returns a sample once there's a previous one to rate against
    /// — the first scrape of a session only establishes a baseline, because a
    /// counter's absolute value ("132348 CPU-seconds since boot") is meaningless
    /// on its own.
    pub fn push(&mut self, raw: RawSample) -> Option<NodeSample> {
        let prev = self.prev.replace(raw.clone())?;

        let dt = (raw.ts - prev.ts) as f64 / 1000.0;
        // Two scrapes in the same instant would divide by zero; a backwards clock
        // is nonsense too.
        if dt <= 0.0 {
            return None;
        }

        // CPU: busy is everything that isn't idle, as a share of elapsed CPU time.
        // Derived from the deltas rather than the totals, so it reflects the
        // interval instead of the average since boot.
        let idle_delta = delta(&raw.cpu_seconds, &prev.cpu_seconds, "idle");
        let total_delta: f64 = raw
            .cpu_seconds
            .keys()
            .map(|mode| delta(&raw.cpu_seconds, &prev.cpu_seconds, mode))
            .sum();
        let cpu_percent = if total_delta > 0.0 {
            (100.0 * (1.0 - idle_delta / total_delta)).clamp(0.0, 100.0)
        } else {
            // The exporter restarted (counters reset), so the deltas are garbage.
            0.0
        };

        Some(NodeSample {
            ts: raw.ts,
            cpu_percent,
            mem_used_bytes: (raw.mem_total - raw.mem_available).max(0.0),
            mem_total_bytes: raw.mem_total,
            net_rx_bps: rate(raw.net_rx, prev.net_rx, dt),
            net_tx_bps: rate(raw.net_tx, prev.net_tx, dt),
            load1: raw.load1,
            load5: raw.load5,
            load15: raw.load15,
            filesystems: raw
                .filesystems
                .iter()
                .map(|(mp, (size, avail))| Filesystem {
                    mountpoint: mp.clone(),
                    used_bytes: (size - avail).max(0.0),
                    size_bytes: *size,
                })
                .collect(),
        })
    }
}

/// Delta of one counter between scrapes, floored at zero.
///
/// A counter that went backwards means it was reset — the exporter restarted, or
/// the node rebooted. The true delta is unknowable, and the difference is a large
/// negative number that would render as a spike; zero is the honest answer.
fn delta(now: &BTreeMap<String, f64>, prev: &BTreeMap<String, f64>, key: &str) -> f64 {
    let (a, b) = (
        now.get(key).copied().unwrap_or(0.0),
        prev.get(key).copied().unwrap_or(0.0),
    );
    (a - b).max(0.0)
}

/// Per-second rate of a counter, with the same reset handling.
fn rate(now: f64, prev: f64, dt_secs: f64) -> f64 {
    ((now - prev).max(0.0)) / dt_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cut-down scrape in the exact shape node-exporter emits, including the
    /// scientific notation it uses for large values.
    fn scrape(cpu_idle: f64, cpu_user: f64, rx: f64, tx: f64) -> String {
        format!(
            r#"# HELP node_cpu_seconds_total Seconds the CPUs spent in each mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{{cpu="0",mode="idle"}} {cpu_idle}
node_cpu_seconds_total{{cpu="0",mode="user"}} {cpu_user}
node_cpu_seconds_total{{cpu="1",mode="idle"}} {cpu_idle}
node_cpu_seconds_total{{cpu="1",mode="user"}} {cpu_user}
node_memory_MemTotal_bytes 6.6421248e+10
node_memory_MemAvailable_bytes 3.3210624e+10
node_network_receive_bytes_total{{device="eth0"}} {rx}
node_network_transmit_bytes_total{{device="eth0"}} {tx}
node_network_receive_bytes_total{{device="lo"}} 9.9e+11
node_network_receive_bytes_total{{device="veth1234"}} 8.8e+11
node_load1 1.5
node_load5 2
node_load15 0.25
node_filesystem_size_bytes{{device="/dev/nvme0n1",fstype="ext4",mountpoint="/"}} 1.0e+12
node_filesystem_avail_bytes{{device="/dev/nvme0n1",fstype="ext4",mountpoint="/"}} 4.0e+11
node_filesystem_size_bytes{{device="tmpfs",fstype="tmpfs",mountpoint="/dev/shm"}} 1.0e+10
node_filesystem_avail_bytes{{device="tmpfs",fstype="tmpfs",mountpoint="/dev/shm"}} 1.0e+10
"#
        )
    }

    #[test]
    fn parses_the_families_we_plot() {
        let s = parse(&scrape(100.0, 50.0, 1000.0, 500.0), 0);
        // Summed across both cores.
        assert_eq!(s.cpu_seconds["idle"], 200.0);
        assert_eq!(s.cpu_seconds["user"], 100.0);
        assert_eq!(s.mem_total, 6.6421248e10, "scientific notation must parse");
        assert_eq!(s.mem_available, 3.3210624e10);
        assert_eq!(s.load1, 1.5);
        assert_eq!(s.load5, 2.0);
        assert_eq!(s.load15, 0.25);
    }

    /// Virtual interfaces are excluded: a pod's traffic crosses both its veth and
    /// the real NIC, so counting both would double it — and the total would lurch
    /// whenever a pod came or went.
    #[test]
    fn counts_only_physical_interfaces() {
        let s = parse(&scrape(100.0, 50.0, 1000.0, 500.0), 0);
        assert_eq!(s.net_rx, 1000.0, "lo and veth must not be summed in");
        assert_eq!(s.net_tx, 500.0);
    }

    #[test]
    fn iface_classification() {
        for real in ["eth0", "enp5s0", "wlan0", "bond0", "eno1"] {
            assert!(is_physical_iface(real), "{real} is a real NIC");
        }
        for virt in [
            "lo",
            "veth9a8b",
            "docker0",
            "flannel.1",
            "cni0",
            "br-abc",
            "cali123",
        ] {
            assert!(!is_physical_iface(virt), "{virt} is virtual");
        }
    }

    /// tmpfs is RAM; showing it as disk usage would be a lie.
    #[test]
    fn keeps_only_real_filesystems() {
        let s = parse(&scrape(100.0, 50.0, 1000.0, 500.0), 0);
        assert!(s.filesystems.contains_key("/"));
        assert!(
            !s.filesystems.contains_key("/dev/shm"),
            "tmpfs is not storage"
        );
        assert_eq!(s.filesystems["/"], (1.0e12, 4.0e11));
    }

    /// Kernel interfaces mounted with a real fstype still aren't storage. murphy-yi
    /// has both of these, and they'd otherwise appear as empty bars.
    #[test]
    fn kernel_mounts_are_not_storage() {
        let m = concat!(
            "node_filesystem_size_bytes{fstype=\"nfsd\",mountpoint=\"/proc/fs/nfsd\"} 0\n",
            "node_filesystem_avail_bytes{fstype=\"nfsd\",mountpoint=\"/proc/fs/nfsd\"} 0\n",
            "node_filesystem_size_bytes{fstype=\"efivarfs\",mountpoint=\"/sys/firmware/efi/efivars\"} 262144\n",
            "node_filesystem_avail_bytes{fstype=\"efivarfs\",mountpoint=\"/sys/firmware/efi/efivars\"} 131072\n",
            "node_filesystem_size_bytes{fstype=\"ext4\",mountpoint=\"/\"} 1000\n",
            "node_filesystem_avail_bytes{fstype=\"ext4\",mountpoint=\"/\"} 400\n",
        );
        let s = parse(m, 0);
        assert_eq!(s.filesystems.len(), 1, "only / is storage");
        assert!(s.filesystems.contains_key("/"));
    }

    /// A zero-byte filesystem would plot as an empty bar and a 0/0 percentage.
    #[test]
    fn zero_sized_filesystems_are_dropped() {
        let m = concat!(
            "node_filesystem_size_bytes{fstype=\"ext4\",mountpoint=\"/empty\"} 0\n",
            "node_filesystem_avail_bytes{fstype=\"ext4\",mountpoint=\"/empty\"} 0\n",
        );
        assert!(parse(m, 0).filesystems.is_empty());
    }

    /// The first scrape can't produce a sample: a counter's absolute value says
    /// nothing without a previous one to difference against.
    #[test]
    fn first_scrape_only_establishes_a_baseline() {
        let mut s = Sampler::default();
        assert_eq!(s.push(parse(&scrape(100.0, 50.0, 1000.0, 500.0), 0)), None);
    }

    /// Busy CPU is computed from the interval's deltas, not the totals since boot.
    #[test]
    fn cpu_percent_is_the_intervals_busy_share() {
        let mut s = Sampler::default();
        s.push(parse(&scrape(100.0, 50.0, 0.0, 0.0), 0));
        // Over the next second: idle +1s per core, user +1s per core → 50% busy.
        let out = s.push(parse(&scrape(101.0, 51.0, 0.0, 0.0), 1000)).unwrap();
        assert!(
            (out.cpu_percent - 50.0).abs() < 1e-9,
            "got {}",
            out.cpu_percent
        );
    }

    /// A fully idle interval reads 0%, not "the average since boot".
    #[test]
    fn idle_cpu_reads_zero() {
        let mut s = Sampler::default();
        s.push(parse(&scrape(100.0, 50.0, 0.0, 0.0), 0));
        let out = s.push(parse(&scrape(102.0, 50.0, 0.0, 0.0), 1000)).unwrap();
        assert_eq!(out.cpu_percent, 0.0);
    }

    /// Network rates are per second, regardless of the poll interval.
    #[test]
    fn network_rate_is_per_second() {
        let mut s = Sampler::default();
        s.push(parse(&scrape(100.0, 50.0, 1000.0, 500.0), 0));
        // 5000 bytes over 5 seconds = 1000 B/s.
        let out = s
            .push(parse(&scrape(101.0, 51.0, 6000.0, 5500.0), 5000))
            .unwrap();
        assert_eq!(out.net_rx_bps, 1000.0);
        assert_eq!(out.net_tx_bps, 1000.0);
    }

    /// A counter that went backwards means the exporter restarted. The delta is
    /// unknowable; zero is honest, where the raw difference would draw a huge
    /// negative spike.
    #[test]
    fn counter_reset_does_not_produce_a_negative_spike() {
        let mut s = Sampler::default();
        s.push(parse(&scrape(100.0, 50.0, 1_000_000.0, 1_000_000.0), 0));
        let out = s.push(parse(&scrape(1.0, 0.5, 10.0, 10.0), 1000)).unwrap();
        assert_eq!(out.net_rx_bps, 0.0);
        assert_eq!(out.net_tx_bps, 0.0);
        assert!(out.cpu_percent >= 0.0 && out.cpu_percent <= 100.0);
    }

    /// Two scrapes at the same instant would divide by zero.
    #[test]
    fn zero_interval_is_dropped() {
        let mut s = Sampler::default();
        s.push(parse(&scrape(100.0, 50.0, 0.0, 0.0), 5000));
        assert_eq!(s.push(parse(&scrape(101.0, 51.0, 0.0, 0.0), 5000)), None);
    }

    /// Memory is reported as used, which is what you want to see; the exporter
    /// only gives total and available.
    #[test]
    fn memory_used_is_total_minus_available() {
        let mut s = Sampler::default();
        s.push(parse(&scrape(100.0, 50.0, 0.0, 0.0), 0));
        let out = s.push(parse(&scrape(101.0, 51.0, 0.0, 0.0), 1000)).unwrap();
        assert_eq!(out.mem_total_bytes, 6.6421248e10);
        assert_eq!(out.mem_used_bytes, 6.6421248e10 - 3.3210624e10);
        assert_eq!(out.filesystems[0].used_bytes, 6.0e11, "size - avail");
    }

    /// Labels are read by key, not by position — the exporter is free to reorder
    /// them, and values can contain commas.
    #[test]
    fn label_lookup_is_positional_agnostic() {
        assert_eq!(
            label(r#"cpu="3",mode="iowait""#, "mode"),
            Some("iowait".into())
        );
        assert_eq!(
            label(r#"mode="iowait",cpu="3""#, "mode"),
            Some("iowait".into())
        );
        assert_eq!(
            label(
                r#"device="/dev/x",mountpoint="/mnt/a,b",fstype="ext4""#,
                "mountpoint"
            ),
            Some("/mnt/a,b".into()),
            "a comma inside a value must not split the label"
        );
        assert_eq!(label(r#"cpu="0""#, "mode"), None);
    }

    /// Junk lines are skipped rather than poisoning a sample.
    #[test]
    fn malformed_lines_are_ignored() {
        let s = parse(
            "node_load1 NaN\nnode_load5 +Inf\ngarbage\nnode_load15 0.5\n",
            0,
        );
        assert_eq!(s.load1, 0.0, "NaN must not land in the series");
        assert_eq!(s.load5, 0.0, "+Inf must not land in the series");
        assert_eq!(s.load15, 0.5);
    }
}
