//! Метрики хоста по SSH (agentless).
//!
//! Одна команда exec читает `/proc/stat`, `/proc/meminfo`, `/proc/net/dev`,
//! `/proc/loadavg` и вывод `df -P /`. Разбор текста — здесь, чистые функции;
//! отправка по SSH — в терминальном потоке (см. `ui/terminal.rs`).
//!
//! CPU и сеть считаются по дельтам между опросами: в `/proc/stat` и
//! `/proc/net/dev` значения — накопительные с момента загрузки.

use std::time::Duration;

/// Снимок показателей хоста.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostMetrics {
    /// Загрузка CPU, 0..100 (по дельтам между опросами).
    pub cpu_percent: Option<f64>,
    /// Занятая память, 0..100.
    pub mem_percent: Option<f64>,
    /// Приём, КБ/с (по дельтам).
    pub rx_kbps: Option<f64>,
    /// Отдача, КБ/с (по дельтам).
    pub tx_kbps: Option<f64>,
    /// Load average за 1 минуту.
    pub load1: Option<f64>,
    /// Занято на корневой ФС, 0..100.
    pub disk_percent: Option<f64>,
}

impl HostMetrics {
    /// Краткая строка для панели вкладки: «CPU 12% · RAM 43% · ↓ 120 ↑ 5 КБ/с».
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(cpu) = self.cpu_percent {
            parts.push(format!("CPU {}%", cpu.round() as i64));
        }
        if let Some(mem) = self.mem_percent {
            parts.push(format!("RAM {}%", mem.round() as i64));
        }
        if self.rx_kbps.is_some() || self.tx_kbps.is_some() {
            parts.push(format!(
                "↓ {} ↑ {} КБ/с",
                fmt_rate(self.rx_kbps),
                fmt_rate(self.tx_kbps)
            ));
        }
        if let Some(load) = self.load1 {
            parts.push(format!("load {load:.2}"));
        }
        if let Some(disk) = self.disk_percent {
            parts.push(format!("/ {}%", disk.round() as i64));
        }
        parts.join(" · ")
    }
}

fn fmt_rate(value: Option<f64>) -> String {
    match value {
        Some(rate) if rate >= 1000.0 => format!("{:.1}М", rate / 1000.0),
        Some(rate) => format!("{}", rate.round() as i64),
        None => "?".to_string(),
    }
}

/// Накопительные счётчики для вычисления дельт.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counters {
    /// (total, idle) из /proc/stat.
    pub cpu: (u64, u64),
    /// (rx_bytes, tx_bytes) из /proc/net/dev, без lo.
    pub net: (u64, u64),
    /// Момент чтения — для точного интервала.
    pub at: Option<std::time::Instant>,
}

/// Команда, которой снимаются все показатели за один exec.
pub const METRICS_COMMAND: &str = "echo ==STAT==; cat /proc/stat 2>/dev/null; \
    echo ==MEM==; cat /proc/meminfo 2>/dev/null; echo ==NET==; cat /proc/net/dev 2>/dev/null; \
    echo ==LOAD==; cat /proc/loadavg 2>/dev/null; echo ==DISK==; df -P / 2>/dev/null; echo ==END==";

/// Сколько ждём вывода команды метрик (неблокирующее чтение).
pub const METRICS_TIMEOUT: Duration = Duration::from_secs(4);

/// Результат одного опроса: показатели и счётчики для следующей дельты.
#[derive(Debug, Clone, Default)]
pub struct MetricsSample {
    pub metrics: HostMetrics,
    pub counters: Counters,
}

/// Разбирает вывод команды метрик и вычисляет дельты по предыдущим счётчикам.
///
/// При первом опросе (`prev = None`) CPU/сеть недоступны — накопительные
/// счётчики ещё не с чем сравнить; возвращаются только память, load и диск.
pub fn sample(text: &str, prev: Option<&Counters>, elapsed: Duration) -> Result<MetricsSample, String> {
    if !text.contains("==END==") {
        return Err("сервер не вернул ожидаемый вывод (/proc или df недоступны)".to_string());
    }

    let mut section = "";
    let mut stat_text = String::new();
    let mut mem_text = String::new();
    let mut net_text = String::new();
    let mut load_text = String::new();
    let mut disk_text = String::new();
    for line in text.lines() {
        if let Some(marker) = section_marker(line) {
            section = marker;
            continue;
        }
        match section {
            "STAT" => { stat_text.push_str(line); stat_text.push('\n'); }
            "MEM" => { mem_text.push_str(line); mem_text.push('\n'); }
            "NET" => { net_text.push_str(line); net_text.push('\n'); }
            "LOAD" => { load_text.push_str(line); load_text.push('\n'); }
            "DISK" => { disk_text.push_str(line); disk_text.push('\n'); }
            _ => {}
        }
    }

    let cpu_counters = stat_text
        .lines()
        .find_map(parse_proc_stat_cpu)
        .ok_or("в /proc/stat нет строки «cpu»")?;
    let net_counters = parse_net_dev(&net_text).unwrap_or((0, 0));

    let counters = Counters {
        cpu: cpu_counters,
        net: net_counters,
        at: Some(std::time::Instant::now()),
    };

    let elapsed = if elapsed.is_zero() { Duration::from_secs(1) } else { elapsed };

    let cpu_percent = match prev {
        Some(prev) => {
            let (total_prev, idle_prev) = prev.cpu;
            let (total, idle) = counters.cpu;
            let dt_total = total.saturating_sub(total_prev);
            let dt_idle = idle.saturating_sub(idle_prev);
            if dt_total > 0 {
                Some((dt_total - dt_idle) as f64 * 100.0 / dt_total as f64)
            } else {
                None
            }
        }
        None => None,
    };

    // КБ/с считаем десятичными (1 КБ = 1000 Б) — так же показывают скорость
    // nload, iftop и большинство сетевых утилит.
    let (rx_percent, tx_percent) = match prev {
        Some(prev) => {
            let dt_rx = counters.net.0.saturating_sub(prev.net.0) as f64 / 1000.0;
            let dt_tx = counters.net.1.saturating_sub(prev.net.1) as f64 / 1000.0;
            let secs = elapsed.as_secs_f64().max(0.001);
            (Some(dt_rx / secs), Some(dt_tx / secs))
        }
        None => (None, None),
    };

    Ok(MetricsSample {
        metrics: HostMetrics {
            cpu_percent,
            mem_percent: parse_meminfo_percent(&mem_text),
            rx_kbps: rx_percent,
            tx_kbps: tx_percent,
            load1: parse_loadavg(&load_text),
            disk_percent: parse_df_root(&disk_text),
        },
        counters,
    })
}

fn section_marker(line: &str) -> Option<&'static str> {
    match line.trim() {
        "==STAT==" => Some("STAT"),
        "==MEM==" => Some("MEM"),
        "==NET==" => Some("NET"),
        "==LOAD==" => Some("LOAD"),
        "==DISK==" => Some("DISK"),
        "==END==" => Some("END"),
        _ => None,
    }
}

/// Строка `cpu  …` из /proc/stat: (total, idle+iowait).
pub fn parse_proc_stat_cpu(line: &str) -> Option<(u64, u64)> {
    let line = line.strip_prefix("cpu ")?.trim();
    let values: Vec<u64> = line.split_whitespace().filter_map(|v| v.parse().ok()).collect();
    if values.is_empty() {
        return None;
    }
    let total: u64 = values.iter().sum();
    let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);
    Some((total, idle))
}

/// Доля занятой памяти из /proc/meminfo.
pub fn parse_meminfo_percent(text: &str) -> Option<f64> {
    let total = meminfo_kb(text, "MemTotal")?;
    let available = meminfo_kb(text, "MemAvailable")?;
    if total == 0 {
        return None;
    }
    let used = total.saturating_sub(available);
    Some(used as f64 * 100.0 / total as f64)
}

fn meminfo_kb(text: &str, key: &str) -> Option<u64> {
    for line in text.lines() {
        let mut parts = line.split(':');
        if parts.next()?.trim() == key {
            let value = parts.next()?.split_whitespace().next()?;
            return value.parse().ok();
        }
    }
    None
}

/// Суммарные байты по интерфейсам из /proc/net/dev (lo не считается).
///
/// Строки, где не хватает полей (в т.ч. шапка таблицы), пропускаются.
pub fn parse_net_dev(text: &str) -> Option<(u64, u64)> {
    let mut rx = 0u64;
    let mut tx = 0u64;
    let mut seen = false;
    for line in text.lines() {
        let Some((iface, stats)) = line.split_once(':') else {
            continue;
        };
        let iface = iface.trim();
        if iface == "lo" || iface.is_empty() {
            continue;
        }
        // Формат строки: iface: rx_bytes rx_packets ... (8 полей) tx_bytes …
        let mut fields = stats.split_whitespace();
        let (Some(rx_bytes), Some(tx_bytes)) = (
            fields.next().and_then(|v| v.parse::<u64>().ok()),
            fields.nth(7).and_then(|v| v.parse::<u64>().ok()),
        ) else {
            continue;
        };
        rx += rx_bytes;
        tx += tx_bytes;
        seen = true;
    }
    seen.then_some((rx, tx))
}

/// Load average за минуту из /proc/loadavg.
pub fn parse_loadavg(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse().ok()
}

/// Заполненность корневой ФС из вывода `df -P /`.
///
/// Строки, где пятая колонка не число (в т.ч. шапка таблицы), пропускаются.
pub fn parse_df_root(text: &str) -> Option<f64> {
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        if let Ok(capacity) = fields[4].trim_end_matches('%').parse::<f64>() {
            return Some(capacity);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
==STAT==
cpu  100 0 50 800 50 0 0 0 0 0
cpu0 10 0 5 80 5 0 0 0 0 0
==MEM==
MemTotal:       16000000 kB
MemAvailable:    8000000 kB
Buffers:          100000 kB
==NET==
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 2000 20 0 0 0 0 0 0 1000 15 0 0 0 0 0 0
==LOAD==
0.42 0.30 0.25 1/233 4242
==DISK==
Filesystem 1024-blocks     Used Available Capacity Mounted on
/dev/sda1     50000000 20000000  30000000      40% /
==END==
";

    #[test]
    fn stat_cpu_sums_all_fields() {
        let (total, idle) = parse_proc_stat_cpu("cpu  100 0 50 800 50 0 0 0 0 0").expect("cpu");
        assert_eq!(total, 1000);
        assert_eq!(idle, 850);
    }

    #[test]
    fn cpu_delta_between_polls() {
        // Между опросами: +100 total, +50 idle → занято 50%.
        let (t0, i0) = parse_proc_stat_cpu("cpu  100 0 50 800 50 0 0 0 0 0").unwrap();
        let (t1, i1) = parse_proc_stat_cpu("cpu  150 0 50 850 50 0 0 0 0 0").unwrap();
        let total = t1 - t0;
        let busy = total - (i1 - i0);
        assert_eq!(busy as f64 * 100.0 / total as f64, 50.0);
    }

    #[test]
    fn meminfo_percent() {
        assert_eq!(parse_meminfo_percent(SAMPLE), Some(50.0));
    }

    #[test]
    fn net_dev_skips_loopback() {
        let (rx, tx) = parse_net_dev(SAMPLE).expect("net");
        assert_eq!(rx, 2000);
        assert_eq!(tx, 1000);
    }

    #[test]
    fn loadavg_first_value() {
        assert_eq!(parse_loadavg("0.42 0.30 0.25 1/233 4242"), Some(0.42));
    }

    #[test]
    fn df_root_capacity() {
        // Только секция df, как её передаёт sample() (в полном SAMPLE
        // есть другие строки из 5+ полей, например «cpu …»).
        const DISK_ONLY: &str = "\
Filesystem 1024-blocks     Used Available Capacity Mounted on
/dev/sda1     50000000 20000000  30000000      40% /
";
        assert_eq!(parse_df_root(DISK_ONLY), Some(40.0));
        // Шапка без чисел не должна ломать разбор.
        assert_eq!(parse_df_root("Filesystem 1024-blocks Used"), None);
    }

    #[test]
    fn first_sample_has_only_static_metrics() {
        let result = sample(SAMPLE, None, Duration::from_secs(5)).expect("sample");
        let m = result.metrics;
        assert_eq!(m.cpu_percent, None);
        assert_eq!(m.mem_percent, Some(50.0));
        assert_eq!(m.load1, Some(0.42));
        assert_eq!(m.disk_percent, Some(40.0));
        assert!(m.summary().contains("RAM 50%"));
    }

    #[test]
    fn second_sample_computes_deltas() {
        let first = sample(SAMPLE, None, Duration::from_secs(0)).expect("first");
        // Между опросами: +1000 total, +500 idle, +10КБ rx, +5КБ tx за 5 с.
        let second_text = SAMPLE
            .replace("cpu  100 0 50 800 50 0 0 0 0 0", "cpu  600 0 50 1300 50 0 0 0 0 0")
            .replace("  eth0: 2000 20 0 0 0 0 0 0 1000 15 0 0 0 0 0 0", "  eth0: 12000 20 0 0 0 0 0 0 6000 15 0 0 0 0 0 0");
        let result = sample(&second_text, Some(&first.counters), Duration::from_secs(5))
            .expect("second");
        let m = result.metrics;
        // 500 занятых из 1000 → 50%.
        assert_eq!(m.cpu_percent, Some(50.0));
        // 10000 rx-байт / 5 с = 2 КБ/с; 5000 tx = 1 КБ/с.
        assert_eq!(m.rx_kbps, Some(2.0));
        assert_eq!(m.tx_kbps, Some(1.0));
    }

    #[test]
    fn broken_output_is_an_error() {
        assert!(sample("что-то другое", None, Duration::from_secs(5)).is_err());
    }
}
