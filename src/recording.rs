//! Запись терминальной сессии в формате утилит `script`(1)/`scriptreplay`(1)
//! из util-linux.
//!
//! Запись состоит из двух файлов (multi-stream формат, см. script-playutils.c):
//!
//! * typescript — сырой вывод сессии; первая строка — заголовок
//!   «Script started on …» (scriptreplay её пропускает), последняя —
//!   «Script done on …»;
//! * timing — по строке на порцию вывода: `O <секунды>.<микросекунды> <размер>`,
//!   где пауза считается от предыдущей записи, а размер — число байт порции;
//!   в конце — служебные записи `H 0.000000 DURATION …` и `H … EXIT_CODE n`.
//!
//! Воспроизведение: `scriptreplay -T <timing> -O <typescript>`.
//! Запись также поддерживает `scriptreplay --summary`.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Предельный размер записи: после него данные перестают попадать в файлы
/// (сессия продолжает работать). Защита от runaway-вывода (например,
/// случайно запущенного `yes`) на root-сессии.
pub const MAX_RECORDING_BYTES: u64 = 256 * 1024 * 1024;

/// Активная запись SSH-сессии.
pub struct Recording {
    out: File,
    timing: File,
    start: Instant,
    prev: Instant,
    limit: u64,
    written: u64,
    full: bool,
    out_path: PathBuf,
    timing_path: PathBuf,
}

impl Recording {
    /// Начинает запись в `dir`: пара файлов `session-<имя>-<время>.log` и `.timing`.
    pub fn start(dir: &Path, command: &str) -> io::Result<Self> {
        Self::start_with_limit(dir, command, MAX_RECORDING_BYTES)
    }

    /// То же с явным лимитом размера (для тестов).
    pub fn start_with_limit(dir: &Path, command: &str, limit: u64) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let (out_path, timing_path) = free_paths(dir, command)?;
        let mut out = File::create(&out_path)?;
        let timing = File::create(&timing_path)?;
        writeln!(
            out,
            "Script started on {} [COMMAND=\"{}\"]",
            iso_now(),
            command.replace('"', "\\\"")
        )?;
        let start = Instant::now();
        Ok(Self {
            out,
            timing,
            start,
            prev: start,
            limit,
            written: 0,
            full: false,
            out_path,
            timing_path,
        })
    }

    /// Записывает порцию вывода: данные — в typescript, пауза и размер — в timing.
    ///
    /// Ошибки диска не прерывают сессию: вызывающий код игнорирует результат,
    /// о неблагополучной записи сообщит logging::warn в finish().
    pub fn write_out(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() || self.full {
            return Ok(());
        }
        if self.written + data.len() as u64 > self.limit {
            self.full = true;
            crate::logging::warn(&format!(
                "запись сессии остановлена: превышен лимит {} байт ({})",
                self.limit,
                self.out_path.display()
            ));
            return Ok(());
        }
        self.out.write_all(data)?;
        let now = Instant::now();
        writeln!(
            self.timing,
            "O {} {}",
            fmt_delay(now - self.prev),
            data.len()
        )?;
        self.prev = now;
        self.written += data.len() as u64;
        Ok(())
    }

    /// Завершает запись: DURATION/EXIT_CODE в timing, итоговая строка — в
    /// typescript. `exit_code` — 0 при штатном закрытии сессии, 1 при ошибке.
    pub fn finish(mut self, exit_code: i32) -> io::Result<()> {
        let total = fmt_delay(self.start.elapsed());
        let res = (|| -> io::Result<()> {
            writeln!(self.timing, "H 0.000000 DURATION {total}")?;
            writeln!(self.timing, "H 0.000000 EXIT_CODE {exit_code}")?;
            writeln!(
                self.out,
                "\nScript done on {} [COMMAND_EXIT_CODE=\"{exit_code}\"]",
                iso_now()
            )?;
            self.timing.flush()?;
            self.out.flush()?;
            Ok(())
        })();
        match &res {
            Ok(()) => crate::logging::info(&format!(
                "запись сессии сохранена: {}",
                self.out_path.display()
            )),
            Err(e) => crate::logging::warn(&format!(
                "ошибка записи сессии {}: {e}",
                self.out_path.display()
            )),
        }
        res
    }

    /// Путь к typescript (для отображения пользователю).
    pub fn out_path(&self) -> &Path {
        &self.out_path
    }

    /// Путь к timing-файлу (для отображения пользователю).
    pub fn timing_path(&self) -> &Path {
        &self.timing_path
    }

    /// Запись достигла лимита и более не пополняется.
    pub fn full(&self) -> bool {
        self.full
    }
}

/// Каталог записей: `$REMOTIX_RECORDINGS_DIR` или `<данные>/recordings`.
pub fn recordings_dir() -> PathBuf {
    match std::env::var("REMOTIX_RECORDINGS_DIR") {
        Ok(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => crate::config::data_dir().join("recordings"),
    }
}

/// Свободная пара путей для новой записи: при совпадении имени добавляется
/// счётчик `-2`, `-3`, …
fn free_paths(dir: &Path, command: &str) -> io::Result<(PathBuf, PathBuf)> {
    // Имя файла собирается как OsString вручную: PathBuf::set_extension
    // заменил бы «расширение», распознав точку в имени хоста
    // (session-example.org-… превратился бы в session-example.log).
    let mut base = dir.join("session-").into_os_string();
    // Имя сессии в файле — хост из COMMAND: читаемое и безопасное.
    base.push(session_slug(command));
    base.push("-");
    base.push(file_stamp());

    let make = |n: Option<u32>, ext: &str| {
        let mut s = base.clone();
        if let Some(n) = n {
            s.push(format!("-{n}"));
        }
        s.push(ext);
        PathBuf::from(s)
    };

    let mut out = make(None, ".log");
    let mut timing = make(None, ".timing");
    let mut n = 2;
    while out.exists() || timing.exists() {
        out = make(Some(n), ".log");
        timing = make(Some(n), ".timing");
        n += 1;
    }
    Ok((out, timing))
}

/// Хост для имени файла: из «ssh user@host» берётся host, прочие символы
/// заменяются на `_`.
fn session_slug(command: &str) -> String {
    let tail = command.strip_prefix("ssh ").unwrap_or(command);
    let host = tail.split('@').next_back().unwrap_or(tail);
    let slug: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if slug.is_empty() {
        "session".to_string()
    } else {
        slug
    }
}

/// Метка времени для имени файла: `YYYYMMDD-HHMMSS-mmm` (UTC).
fn file_stamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let (y, m, d) = civil_from_days((secs / 86400) as i64);
    let day = secs % 86400;
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}-{:03}",
        day / 3600,
        (day % 3600) / 60,
        day % 60,
        now.subsec_millis()
    )
}

/// Момент «сейчас» в ISO-виде: `YYYY-MM-DD HH:MM:SS UTC`.
fn iso_now() -> String {
    iso_timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default(),
    )
}

/// ISO-вид момента (UTC): «1970-01-01 00:00:00 UTC».
fn iso_timestamp(since_epoch: Duration) -> String {
    let secs = since_epoch.as_secs();
    let (y, m, d) = civil_from_days((secs / 86400) as i64);
    let day = secs % 86400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        day / 3600,
        (day % 3600) / 60,
        day % 60
    )
}

/// Дата по числу дней от 1970-01-01 (алгоритм Howard Hinnant, civil_from_days).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Пауза в формате util-linux: `<секунды>.<микросекунды, ровно 6 цифр>`.
fn fmt_delay(d: Duration) -> String {
    format!("{}.{:06}", d.as_secs(), d.subsec_micros())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::process::{Command, Stdio};

    /// Уникальный временный каталог для теста.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "remotix-rec-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn iso_timestamp_known_values() {
        assert_eq!(iso_timestamp(Duration::ZERO), "1970-01-01 00:00:00 UTC");
        // 1 000 000 000 с от эпохи
        assert_eq!(
            iso_timestamp(Duration::from_secs(1_000_000_000)),
            "2001-09-09 01:46:40 UTC"
        );
        // Високосный день
        assert_eq!(
            iso_timestamp(Duration::from_secs(1_709_164_800)),
            "2024-02-29 00:00:00 UTC"
        );
    }

    #[test]
    fn timing_format_roundtrip() {
        let dir = temp_dir("format");
        let mut rec = Recording::start(&dir, "ssh tester@example.org").unwrap();
        let out_path = rec.out_path().to_path_buf();
        let timing_path = rec.timing_path().to_path_buf();
        rec.write_out(b"abc").unwrap();
        std::thread::sleep(Duration::from_millis(10));
        rec.write_out(b"def").unwrap();
        rec.finish(3).unwrap();

        let timing = std::fs::read_to_string(&timing_path).unwrap();
        let mut total = 0u64;
        let mut o_lines = 0;
        for line in timing.lines() {
            match line.split_once(' ') {
                Some(("O", rest)) => {
                    o_lines += 1;
                    let (delay, size) = rest.split_once(' ').unwrap();
                    // Пауза: <сек>.<ровно 6 цифр> — формат parser'а scriptreplay.
                    let (sec, usec) = delay.split_once('.').unwrap();
                    assert!(sec.parse::<u64>().is_ok());
                    assert_eq!(usec.len(), 6, "микросекунды ровно 6 цифр: {delay}");
                    assert!(usec.parse::<u32>().unwrap() < 1_000_000);
                    total += size.parse::<u64>().unwrap();
                }
                Some(("H", _)) => {}
                other => panic!("неожиданная строка timing: {other:?}"),
            }
        }
        assert_eq!(o_lines, 2);
        assert_eq!(total, 6, "сумма размеров = объём данных");
        assert!(timing.ends_with("H 0.000000 EXIT_CODE 3\n"));

        let typescript = std::fs::read_to_string(&out_path).unwrap();
        assert!(
            typescript.starts_with("Script started on 20"),
            "заголовок typescript: {typescript:?}"
        );
        assert!(typescript.contains("COMMAND=\"ssh tester@example.org\""));
        assert!(typescript.contains("abcdef"));
        assert!(typescript.ends_with("[COMMAND_EXIT_CODE=\"3\"]\n"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn limit_stops_recording() {
        let dir = temp_dir("limit");
        let mut rec = Recording::start_with_limit(&dir, "ssh host", 4).unwrap();
        let out_path = rec.out_path().to_path_buf();
        let timing_path = rec.timing_path().to_path_buf();
        rec.write_out(b"1234").unwrap();
        assert!(!rec.full());
        rec.write_out(b"5678").unwrap();
        assert!(rec.full());
        rec.finish(0).unwrap();

        let typescript = std::fs::read_to_string(&out_path).unwrap();
        assert!(typescript.contains("1234"));
        assert!(
            !typescript.contains("5678"),
            "данные сверх лимита не пишутся"
        );

        let timing = std::fs::read_to_string(&timing_path).unwrap();
        let o_count = timing.lines().filter(|l| l.starts_with("O ")).count();
        assert_eq!(o_count, 1, "порция сверх лимита не попадает в timing");
        assert!(timing.contains("H 0.000000 EXIT_CODE 0"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn free_paths_avoids_collision() {
        let dir = temp_dir("collision");
        let (out1, timing1) = free_paths(&dir, "ssh alpha").unwrap();
        std::fs::File::create(&out1).unwrap();
        let (out2, _) = free_paths(&dir, "ssh alpha").unwrap();
        assert_ne!(out1, out2);
        assert_ne!(timing1, PathBuf::from(&out2));
        assert!(out2.to_string_lossy().contains("-2.log"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Точка в имени хоста — не «расширение»: метка времени в имени файла
    /// сохраняется (регрессия: set_extension превращал
    /// session-example.org-…log в session-example.log).
    #[test]
    fn free_paths_keeps_host_dots() {
        let dir = temp_dir("dots");
        let (out, timing) = free_paths(&dir, "ssh tester@example.org").unwrap();
        let name = out.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("session-example.org-"), "имя: {name}");
        assert!(name.ends_with(".log"), "имя: {name}");
        assert!(name.contains('-'), "метка времени потеряна: {name}");
        let tname = timing.file_name().unwrap().to_string_lossy().into_owned();
        assert!(tname.ends_with(".timing"), "имя: {tname}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn session_slug_from_command() {
        assert_eq!(session_slug("ssh root@10.0.0.1"), "10.0.0.1");
        assert_eq!(session_slug("ssh tester@example.org"), "example.org");
        assert_eq!(session_slug("ssh host"), "host");
        assert_eq!(session_slug(""), "session");
        assert_eq!(session_slug("ssh user@мой сервер"), "__________");
    }

    /// Полная совместимость: scriptreplay восстанавливает ровно записанный
    /// вывод (плюс финальный перевод строки, который scriptreplay всегда
    /// печатает после воспроизведения). Пропускается, если scriptreplay
    /// в системе нет.
    #[test]
    fn scriptreplay_reproduces_output() {
        if Command::new("scriptreplay")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            println!("scriptreplay недоступен — тест пропущен");
            return;
        }

        let dir = temp_dir("replay");
        let mut rec = Recording::start(&dir, "ssh replay-test").unwrap();
        let out_path = rec.out_path().to_path_buf();
        let timing_path = rec.timing_path().to_path_buf();
        let mut payload: Vec<u8> = Vec::new();
        for chunk in [
            &b"hello "[..],
            &b"world\n"[..],
            &b"\x1b[1mbright\x1b[0m\n"[..],
            &b"$ "[..],
        ] {
            rec.write_out(chunk).unwrap();
            payload.extend_from_slice(chunk);
            std::thread::sleep(Duration::from_millis(15));
        }
        rec.finish(0).unwrap();

        let out = Command::new("scriptreplay")
            .arg("-T")
            .arg(&timing_path)
            .arg("-O")
            .arg(&out_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "scriptreplay завершился ошибкой");

        let mut expected = payload;
        expected.push(b'\n'); // scriptreplay в конце всегда печатает "\n"
        assert_eq!(out.stdout, expected);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// scriptreplay --summary должен разбирать служебные записи DURATION/EXIT_CODE.
    #[test]
    fn scriptreplay_summary_parses_headers() {
        if Command::new("scriptreplay")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            println!("scriptreplay недоступен — тест пропущен");
            return;
        }

        let dir = temp_dir("summary");
        let mut rec = Recording::start(&dir, "ssh summary-test").unwrap();
        let out_path = rec.out_path().to_path_buf();
        let timing_path = rec.timing_path().to_path_buf();
        rec.write_out(b"out\n").unwrap();
        std::thread::sleep(Duration::from_millis(15));
        rec.finish(7).unwrap();

        let out = Command::new("scriptreplay")
            .arg("--summary")
            .arg("-T")
            .arg(&timing_path)
            .arg("-O")
            .arg(&out_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("DURATION"),
            "в summary нет DURATION: {stdout}"
        );
        assert!(
            stdout.contains("EXIT_CODE"),
            "в summary нет EXIT_CODE: {stdout}"
        );
        assert!(stdout.contains('7'), "в summary нет кода выхода: {stdout}");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Читаемость typescript как текстового файла (для ручного разбора).
    #[test]
    fn typescript_is_raw_bytes() {
        let dir = temp_dir("raw");
        let mut rec = Recording::start(&dir, "ssh raw").unwrap();
        let out_path = rec.out_path().to_path_buf();
        let bytes: Vec<u8> = (0u8..=255).collect();
        rec.write_out(&bytes).unwrap();
        rec.finish(0).unwrap();

        let mut on_disk = Vec::new();
        File::open(&out_path)
            .unwrap()
            .read_to_end(&mut on_disk)
            .unwrap();
        // Заголовок первой строкой, итоговая строка — после данных.
        let header = b"Script started on 2";
        assert!(on_disk.starts_with(header));
        let first_line_len = on_disk.iter().position(|&b| b == b'\n').unwrap() + 1;
        let done_marker = b"\nScript done on ";
        let done_pos = on_disk
            .windows(done_marker.len())
            .position(|w| w == done_marker)
            .unwrap();
        // Между заголовком и итоговой строкой — исходные байты 0..=255 без изменений.
        assert_eq!(&on_disk[first_line_len..done_pos], &bytes);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
