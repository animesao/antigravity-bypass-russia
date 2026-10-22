//! Rank substituted proxy IPs by TLS speed and keep a short fallback list.
//!
//! Certificate and HTTP checks run when the user enables the bypass.
//! No scheduled rescans or model-response measurements.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::hosts::write_entries as write_hosts_entries;
use crate::net::provider::NRPT_AGENT;
use crate::net::relay;
use crate::net::resolvers;
use crate::net::routes;

const MAX_FALLBACKS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankedHost {
    pub host: String,
    pub ips: Vec<(Ipv4Addr, u128)>,
}

pub fn rank_path() -> PathBuf {
    relay::log_dir().join("proxy_rank.conf")
}

pub fn discover_agent(if_index: u32) -> Result<Vec<RankedHost>, String> {
    let previous = load();
    let geohide_enabled = super::resolver_pool::load()?
        .iter()
        .any(|p| p.name == "geohide.ru");
    let mut ranked = Vec::new();
    for name in NRPT_AGENT {
        let host = name.trim_start_matches('.').to_string();
        let mut candidates = resolvers::candidate_addrs(&host, if_index)?;
        if let Some(old) = previous.iter().find(|h| h.host == host) {
            for (ip, _) in &old.ips {
                let a = IpAddr::V4(*ip);
                if !candidates.contains(&a) {
                    candidates.push(a);
                }
            }
        }
        for seed in crate::net::provider::GEOHIDE_PROXY_V4
            .iter()
            .filter(|_| geohide_enabled)
        {
            if let Ok(v4) = seed.parse::<Ipv4Addr>() {
                let a = IpAddr::V4(v4);
                if !candidates.contains(&a) {
                    candidates.push(a);
                }
            }
        }
        // Test the same physical path that will be used after pinning. Custom
        // DoH answers can introduce proxy IPs absent from the built-in routes.
        let candidates: Vec<_> = candidates
            .into_iter()
            .filter(IpAddr::is_ipv4)
            .take(32)
            .collect();
        let addresses: Vec<_> = candidates
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(ip) => Some(*ip),
                _ => None,
            })
            .collect();
        routes::sync_physical_hosts(&addresses)?;
        let mut ips = resolvers::rank_tls_v4(&candidates, &host);
        if ips.is_empty() {
            continue;
        }
        if ips.len() > MAX_FALLBACKS {
            ips.truncate(MAX_FALLBACKS);
        }
        ranked.push(RankedHost { host, ips });
    }
    if ranked.iter().all(|h| h.ips.is_empty()) {
        // hosts takes precedence over NRPT, so a pin left from a previous run
        // keeps Antigravity broken even when every current probe failed.
        return Err(match release_dead_pins() {
            Ok(true) => {
                "Нет проверенных маршрутов; закреплённые адреса не отвечают и убраны из hosts — используется DNS без привязки к IP".into()
            }
            Ok(false) => "Нет проверенных маршрутов; прежние hosts и рейтинг сохранены".into(),
            Err(failure) => format!(
                "Нет проверенных маршрутов; прежние hosts и рейтинг сохранены, освободить закреплённые адреса не удалось: {failure}"
            ),
        });
    }
    Ok(ranked)
}

/// Release the installed hosts block only when every pinned address failed both
/// probes. A single answering pin is a working configuration and stays as is.
fn release_dead_pins() -> Result<bool, String> {
    let entries = crate::net::hosts::owned_entries()?;
    let dead = pins_unreachable(&entries, |host, ip| {
        crate::net::health::probe_ip(SocketAddr::new(IpAddr::V4(ip), 443), host)
    });
    if dead {
        crate::net::hosts::remove_entries()?;
    }
    Ok(dead)
}

fn pins_unreachable(
    entries: &[(String, Ipv4Addr)],
    probe: impl Fn(&str, Ipv4Addr) -> Result<u128, String> + Sync,
) -> bool {
    if entries.is_empty() {
        return false;
    }
    // Probe every pin concurrently so a fully dead block costs two budgets,
    // not one budget per pinned host.
    std::thread::scope(|scope| {
        let jobs: Vec<_> = entries
            .iter()
            .map(|(host, ip)| {
                let probe = &probe;
                scope.spawn(move || (0..2).all(|_| probe(host, *ip).is_err()))
            })
            .collect();
        jobs.into_iter().all(|job| job.join().unwrap_or(false))
    })
}

pub fn apply_ranked(ranked: &[RankedHost]) -> Result<(), String> {
    routes::sync_physical_hosts(&ranked_ips(ranked))?;
    save(ranked)?;
    apply_hosts(ranked)
}

pub fn format_notes(ranked: &[RankedHost]) -> Vec<String> {
    ranked
        .iter()
        .map(|h| {
            let list = h
                .ips
                .iter()
                .map(|(ip, ms)| format!("{ip} {ms}мс"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} → {}", h.host, list)
        })
        .collect()
}

fn ranked_ips(ranked: &[RankedHost]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for h in ranked {
        for (ip, _) in &h.ips {
            if !out.contains(ip) {
                out.push(*ip);
            }
        }
    }
    out
}

fn apply_hosts(ranked: &[RankedHost]) -> Result<(), String> {
    let mut entries: Vec<(String, Ipv4Addr)> = Vec::new();
    for h in ranked {
        // Pin ONLY the single fastest leader IP for each host into hosts file.
        // This prevents Windows getaddrinfo and Electron Happy Eyeballs from attempting
        // slower fallback IPs and causing 1-3s connection stalling.
        if let Some((best_ip, _)) = h.ips.first() {
            entries.push((h.host.clone(), *best_ip));
        }
    }
    if !entries.is_empty() {
        write_hosts_entries(&entries)?;
    }
    Ok(())
}

fn save(ranked: &[RankedHost]) -> Result<(), String> {
    let dir = relay::log_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut out = format!("# antigravity-proxy-rank 1\n# ts={ts}\n");
    for h in ranked {
        for (ip, ms) in &h.ips {
            out.push_str(&format!("{} {} {}\n", h.host, ip, ms));
        }
    }
    crate::system::fs_utils::robust_write_file(&rank_path(), out.as_bytes())
}

fn load() -> Vec<RankedHost> {
    let Ok(text) = fs::read_to_string(rank_path()) else {
        return Vec::new();
    };
    let mut ranked: Vec<RankedHost> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(host) = parts.next() else { continue };
        let Some(ip) = parts.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        let ms = parts
            .next()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        if let Some(existing) = ranked.iter_mut().find(|h| h.host == host) {
            if !existing.ips.iter().any(|(x, _)| *x == ip) {
                existing.ips.push((ip, ms));
            }
        } else {
            ranked.push(RankedHost {
                host: host.to_string(),
                ips: vec![(ip, ms)],
            });
        }
    }
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, Ipv4Addr)> {
        pairs
            .iter()
            .map(|(host, ip)| ((*host).to_string(), ip.parse().unwrap()))
            .collect()
    }

    #[test]
    fn no_pins_are_never_released() {
        assert!(!pins_unreachable(&[], |_, _| -> Result<u128, String> {
            panic!("probe must not run without pinned entries")
        }));
    }

    #[test]
    fn every_pin_must_fail_twice_before_release() {
        let pinned = entries(&[("cloudcode-pa.googleapis.com", "192.0.2.1")]);
        let probes = AtomicUsize::new(0);
        assert!(pins_unreachable(&pinned, |_, _| {
            probes.fetch_add(1, Ordering::Relaxed);
            Err("TLS: reset".into())
        }));
        assert_eq!(probes.load(Ordering::Relaxed), 2);

        let probes = AtomicUsize::new(0);
        assert!(!pins_unreachable(&pinned, |_, _| {
            probes.fetch_add(1, Ordering::Relaxed);
            Ok(12)
        }));
        assert_eq!(probes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn one_responding_pin_keeps_the_working_block() {
        let pinned = entries(&[
            ("cloudcode-pa.googleapis.com", "192.0.2.1"),
            ("generativelanguage.googleapis.com", "192.0.2.2"),
        ]);
        let attempts = Mutex::new(std::collections::HashMap::new());
        let dead = pins_unreachable(&pinned, |host, _| {
            let mut attempts = attempts.lock().unwrap();
            let attempt = attempts.entry(host.to_string()).or_insert(0);
            *attempt += 1;
            if host == "generativelanguage.googleapis.com" && *attempt == 2 {
                Ok(40)
            } else {
                Err("TLS: reset".into())
            }
        });
        assert!(!dead);
        let attempts = attempts.into_inner().unwrap();
        assert_eq!(attempts["cloudcode-pa.googleapis.com"], 2);
        // A transient first failure is retried instead of releasing the pin.
        assert_eq!(attempts["generativelanguage.googleapis.com"], 2);
    }
}
