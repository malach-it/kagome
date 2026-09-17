use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::config::{RateLimitConfig, RateLimitTimeUnit};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    AllowAfter(Duration),
    Reject,
}

#[derive(Debug)]
pub struct RateLimiter {
    entries: Mutex<HashMap<IpAddr, Vec<u64>>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            config,
        }
    }

    pub fn throttle(&self, ip: IpAddr) -> Decision {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return Decision::Reject;
        };
        self.throttle_at(ip, now.as_millis().try_into().unwrap_or(u64::MAX))
    }

    fn throttle_at(&self, ip: IpAddr, now: u64) -> Decision {
        let unit = self.config.time_unit.milliseconds();
        let horizon = unit.saturating_mul(self.config.memory_length as u64);
        let cutoff = now.saturating_sub(horizon);
        let Ok(mut entries) = self.entries.lock() else {
            return Decision::Reject;
        };

        entries.retain(|_, timestamps| {
            timestamps.retain(|timestamp| *timestamp > cutoff);
            !timestamps.is_empty()
        });
        let timestamps = entries.entry(ip).or_default();
        let timeout = throttling_timeout(timestamps, now, &self.config);

        if timeout >= self.config.timeout {
            return Decision::Reject;
        }

        timestamps.push(now);
        Decision::AllowAfter(Duration::from_millis(timeout))
    }
}

fn throttling_timeout(timestamps: &[u64], now: u64, config: &RateLimitConfig) -> u64 {
    let unit = config.time_unit.milliseconds();
    let mut factor = 1.0_f64;

    for offset in (0..config.memory_length).rev() {
        let bucket = now.saturating_sub((offset as u64).saturating_mul(unit)) / unit;
        let requests = timestamps
            .iter()
            .filter(|timestamp| **timestamp / unit == bucket)
            .count();
        if requests > 0 {
            factor *= requests as f64 / config.count as f64;
        }
    }

    if factor <= 1.0 {
        0
    } else {
        (factor * config.penality as f64).floor() as u64
    }
}

impl RateLimitTimeUnit {
    fn milliseconds(self) -> u64 {
        match self {
            Self::Millisecond => 1,
            Self::Second => 1_000,
            Self::Minute => 60_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RateLimitConfig {
        RateLimitConfig {
            count: 2,
            time_unit: RateLimitTimeUnit::Second,
            penality: 500,
            timeout: 5_000,
            memory_length: 2,
        }
    }

    #[test]
    fn applies_boruta_penalty() {
        let limiter = RateLimiter::new(config());
        let ip = "127.0.0.1".parse().unwrap();

        assert_eq!(
            limiter.throttle_at(ip, 1_000),
            Decision::AllowAfter(Duration::ZERO)
        );
        assert_eq!(
            limiter.throttle_at(ip, 1_001),
            Decision::AllowAfter(Duration::ZERO)
        );
        assert_eq!(
            limiter.throttle_at(ip, 1_002),
            Decision::AllowAfter(Duration::ZERO)
        );
        assert_eq!(
            limiter.throttle_at(ip, 1_003),
            Decision::AllowAfter(Duration::from_millis(750))
        );
    }

    #[test]
    fn separates_clients_by_ip() {
        let limiter = RateLimiter::new(config());
        assert_eq!(
            limiter.throttle_at("127.0.0.1".parse().unwrap(), 1_000),
            Decision::AllowAfter(Duration::ZERO)
        );
        assert_eq!(
            limiter.throttle_at("127.0.0.2".parse().unwrap(), 1_000),
            Decision::AllowAfter(Duration::ZERO)
        );
    }
}
