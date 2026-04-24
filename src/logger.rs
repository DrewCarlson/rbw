//! Minimal RUST_LOG-compatible logger writing `LEVEL: message` to stderr.

use std::io::Write as _;
use std::sync::OnceLock;

use log::{LevelFilter, Log, Metadata, Record};

struct Logger {
    default: LevelFilter,
    modules: Vec<(String, LevelFilter)>,
}

impl Logger {
    fn level_for(&self, target: &str) -> LevelFilter {
        let mut best: Option<(usize, LevelFilter)> = None;
        for (module, lvl) in &self.modules {
            let matches = target == module
                || (target.starts_with(module)
                    && target.as_bytes().get(module.len()) == Some(&b':'));
            if matches && best.is_none_or(|(len, _)| module.len() > len) {
                best = Some((module.len(), *lvl));
            }
        }
        best.map_or(self.default, |(_, l)| l)
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.level_for(metadata.target()) >= metadata.level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let stderr = std::io::stderr();
        let mut h = stderr.lock();
        let _ = writeln!(h, "{}: {}", record.level(), record.args());
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

fn parse_level(s: &str) -> Option<LevelFilter> {
    match s.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}

fn parse_spec(
    spec: &str,
    fallback: LevelFilter,
) -> (LevelFilter, Vec<(String, LevelFilter)>) {
    let mut default = fallback;
    let mut modules = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if let Some((module, lvl)) = part.split_once('=') {
            if let Some(lvl) = parse_level(lvl) {
                modules.push((module.trim().to_string(), lvl));
            }
        } else if let Some(lvl) = parse_level(part) {
            default = lvl;
        }
    }
    (default, modules)
}

/// Initialize the global logger from `RUST_LOG`, using `default_level` if unset.
pub fn init(default_level: &str) {
    let fallback = parse_level(default_level).unwrap_or(LevelFilter::Info);
    let spec = std::env::var("RUST_LOG").unwrap_or_default();
    let (default, modules) = parse_spec(&spec, fallback);

    let max = modules
        .iter()
        .map(|(_, l)| *l)
        .chain(std::iter::once(default))
        .max()
        .unwrap_or(LevelFilter::Off);

    let logger = LOGGER.get_or_init(|| Logger { default, modules });

    let _ = log::set_logger(logger);
    log::set_max_level(max);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_level() {
        let (d, m) = parse_spec("debug", LevelFilter::Info);
        assert_eq!(d, LevelFilter::Debug);
        assert!(m.is_empty());
    }

    #[test]
    fn default_and_modules() {
        let (d, m) = parse_spec("info,rbw=debug", LevelFilter::Warn);
        assert_eq!(d, LevelFilter::Info);
        assert_eq!(m, vec![("rbw".to_string(), LevelFilter::Debug)]);
    }

    #[test]
    fn trailing_default() {
        let (d, m) = parse_spec("rbw_agent=trace,warn", LevelFilter::Info);
        assert_eq!(d, LevelFilter::Warn);
        assert_eq!(
            m,
            vec![("rbw_agent".to_string(), LevelFilter::Trace)]
        );
    }

    #[test]
    fn empty_uses_fallback() {
        let (d, m) = parse_spec("", LevelFilter::Info);
        assert_eq!(d, LevelFilter::Info);
        assert!(m.is_empty());
    }

    #[test]
    fn level_for_module_prefix() {
        let logger = Logger {
            default: LevelFilter::Warn,
            modules: vec![("rbw".to_string(), LevelFilter::Debug)],
        };
        assert_eq!(logger.level_for("rbw"), LevelFilter::Debug);
        assert_eq!(logger.level_for("rbw::config"), LevelFilter::Debug);
        assert_eq!(logger.level_for("other"), LevelFilter::Warn);
        assert_eq!(logger.level_for("rbwx"), LevelFilter::Warn);
    }
}
