use serde_json::{Value, json};
use std::{fs, mem::MaybeUninit};

fn read(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|_| format!("cannot read {path}"))
}
fn emit(metrics: &mut String, name: &str, labels: &str, value: f64, counter: bool) {
    if !metrics.contains(&format!("# TYPE {name} ")) {
        metrics.push_str(&format!(
            "# TYPE {name} {}\n",
            if counter { "counter" } else { "gauge" }
        ));
    }
    metrics.push_str(&format!("{name}{labels} {value}\n"));
}
pub fn collect(previous: &Value) -> Result<(Value, String), String> {
    let mut metrics = String::new();
    // sysconf returns clock ticks per second for /proc/stat counters.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        return Err("invalid clock tick rate".into());
    }
    let stat = read("/proc/stat")?;
    let mut total = 0_u64;
    let mut idle = 0_u64;
    let modes = [
        "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
    ];
    for line in stat.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields[0] == "cpu" {
            let vals: Vec<u64> = fields
                .iter()
                .skip(1)
                .take(8)
                .map(|s| s.parse().unwrap_or(0))
                .collect();
            total = vals.iter().sum();
            idle = vals.get(3).unwrap_or(&0) + vals.get(4).unwrap_or(&0);
        } else if let Some(cpu) = fields[0].strip_prefix("cpu") {
            if !cpu.is_empty() && cpu.bytes().all(|c| c.is_ascii_digit()) {
                for (mode, value) in modes.iter().zip(fields.iter().skip(1)) {
                    let value: u64 = value.parse().map_err(|_| "invalid cpu counter")?;
                    emit(
                        &mut metrics,
                        "node_cpu_seconds_total",
                        &format!("{{cpu=\"{cpu}\",mode=\"{mode}\"}}"),
                        value as f64 / ticks as f64,
                        true,
                    );
                }
            }
        } else if fields[0] == "btime" {
            emit(
                &mut metrics,
                "node_boot_time_seconds",
                "",
                fields[1].parse().map_err(|_| "invalid boot time")?,
                false,
            );
        }
    }
    let busy = previous["cpuTotalTicks"]
        .as_u64()
        .zip(previous["cpuIdleTicks"].as_u64())
        .and_then(|(old_total, old_idle)| {
            let elapsed = total.checked_sub(old_total)?;
            let waiting = idle.checked_sub(old_idle)?;
            (elapsed > 0 && waiting <= elapsed)
                .then(|| 100.0 * (elapsed - waiting) as f64 / elapsed as f64)
        });
    let mut memory = serde_json::Map::new();
    for line in read("/proc/meminfo")?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let name = fields[0].trim_end_matches(':');
        let value: u64 = fields[1].parse().map_err(|_| "invalid memory counter")?;
        let bytes = if fields.get(2) == Some(&"kB") {
            value.saturating_mul(1024)
        } else {
            continue;
        };
        memory.insert(name.into(), json!(bytes));
        emit(
            &mut metrics,
            &format!(
                "node_memory_{}_bytes",
                name.replace('(', "_").replace(')', "")
            ),
            "",
            bytes as f64,
            false,
        );
    }
    let load = read("/proc/loadavg")?;
    let loads: Vec<f64> = load
        .split_whitespace()
        .take(3)
        .map(|s| s.parse().unwrap_or(0.0))
        .collect();
    for (name, value) in ["node_load1", "node_load5", "node_load15"]
        .iter()
        .zip(&loads)
    {
        emit(&mut metrics, name, "", *value, false);
    }
    let uptime: f64 = read("/proc/uptime")?
        .split_whitespace()
        .next()
        .ok_or("missing uptime")?
        .parse()
        .map_err(|_| "invalid uptime")?;
    emit(&mut metrics, "node_uptime_seconds", "", uptime, false);
    let mut networks = Vec::new();
    for line in read("/proc/net/dev")?.lines().skip(2) {
        let Some((device, values)) = line.split_once(':') else {
            continue;
        };
        let device = device.trim();
        let values: Vec<u64> = values
            .split_whitespace()
            .map(|s| s.parse().unwrap_or(0))
            .collect();
        if values.len() < 16 {
            return Err("invalid network counters".into());
        }
        let labels = format!("{{device=\"{}\"}}", super::escape(device));
        for (direction, start) in [("receive", 0), ("transmit", 8)] {
            for (suffix, index) in [("bytes", 0), ("packets", 1), ("errs", 2), ("drop", 3)] {
                emit(
                    &mut metrics,
                    &format!("node_network_{direction}_{suffix}_total"),
                    &labels,
                    values[start + index] as f64,
                    true,
                );
            }
        }
        networks.push(json!({"name":device,"rxBytes":values[0],"txBytes":values[8]}));
    }
    for line in read("/proc/diskstats")?.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() < 14 {
            continue;
        }
        let labels = format!("{{device=\"{}\"}}", super::escape(f[2]));
        for (name, index, factor) in [
            ("reads_completed", 3, 1.0),
            ("read_bytes", 5, 512.0),
            ("read_time_seconds", 6, 0.001),
            ("writes_completed", 7, 1.0),
            ("written_bytes", 9, 512.0),
            ("write_time_seconds", 10, 0.001),
            ("io_time_seconds", 12, 0.001),
        ] {
            let value: u64 = f[index].parse().map_err(|_| "invalid disk counter")?;
            emit(
                &mut metrics,
                &format!("node_disk_{name}_total"),
                &labels,
                value as f64 * factor,
                true,
            );
        }
    }
    let mounts = read("/proc/mounts")?;
    let root = mounts
        .lines()
        .find_map(|line| {
            let f: Vec<_> = line.split_whitespace().collect();
            (f.len() >= 3 && f[1] == "/").then(|| (f[0].to_string(), f[2].to_string()))
        })
        .ok_or("missing root mount")?;
    let mut info = MaybeUninit::<libc::statvfs>::uninit();
    // statvfs initializes the entire structure on success; fixed NUL-terminated root path.
    if unsafe { libc::statvfs(c"/".as_ptr(), info.as_mut_ptr()) } != 0 {
        return Err("root filesystem stat failed".into());
    }
    let info = unsafe { info.assume_init() };
    let size = info.f_blocks.saturating_mul(info.f_frsize);
    let available = info.f_bavail.saturating_mul(info.f_frsize);
    let labels = format!(
        "{{device=\"{}\",fstype=\"{}\",mountpoint=\"/\"}}",
        super::escape(&root.0),
        super::escape(&root.1)
    );
    for (name, value) in [
        ("size_bytes", size),
        ("avail_bytes", available),
        ("free_bytes", info.f_bfree.saturating_mul(info.f_frsize)),
        ("files", info.f_files),
        ("files_free", info.f_ffree),
    ] {
        emit(
            &mut metrics,
            &format!("node_filesystem_{name}"),
            &labels,
            value as f64,
            false,
        );
    }
    Ok((
        json!({"cpuBusyPercent":busy,"cpuTotalTicks":total,"cpuIdleTicks":idle,"memory":memory,"load":loads,"uptimeSeconds":uptime,"rootSizeBytes":size,"rootAvailableBytes":available,"network":networks}),
        metrics,
    ))
}
#[cfg(test)]
mod tests {
    #[test]
    fn linux_host_snapshot() {
        let (first, metrics) = super::collect(&serde_json::Value::Null).unwrap();
        assert!(first["memory"]["MemTotal"].as_u64().unwrap() > 0);
        assert!(first["rootSizeBytes"].as_u64().unwrap() > 0);
        assert!(metrics.contains("node_cpu_seconds_total{cpu=\"0\""));
        assert!(metrics.contains("node_network_receive_bytes_total"));
        assert!(metrics.contains("node_disk_read_bytes_total"));
        assert!(first["cpuBusyPercent"].is_null());
    }
}
