//! Process-local measurements without labels supplied by callers.

use std::{sync::atomic::AtomicU64, time::Instant};

use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

pub const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

pub struct Metrics {
    registry: Registry,
    connection: Histogram,
    audit: Histogram,
    audit_failures: Counter,
    active: Gauge,
    refused: Counter,
    uploaded: Counter,
    downloaded: Counter,
    storage_reserved: Gauge<u64, AtomicU64>,
    storage_items: Gauge<u64, AtomicU64>,
    local_snapshots: Gauge<u64, AtomicU64>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::default();
        let connection = Histogram::new([0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 15.0]);
        let audit = Histogram::new([0.0001, 0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]);
        let audit_failures = Counter::default();
        let active = Gauge::default();
        let refused = Counter::default();
        let uploaded = Counter::default();
        let downloaded = Counter::default();
        let storage_reserved = Gauge::default();
        let storage_items = Gauge::default();
        let local_snapshots = Gauge::default();
        registry.register(
            "ssh_connection_setup_seconds",
            "Complete connection setup duration, including failed or cancelled attempts",
            connection.clone(),
        );
        registry.register(
            "ssh_audit_ack_seconds",
            "Required sink acknowledgement duration",
            audit.clone(),
        );
        registry.register(
            "ssh_audit_failures",
            "Required audit sink failures",
            audit_failures.clone(),
        );
        registry.register(
            "ssh_active_runs",
            "Remote operation readers still executing",
            active.clone(),
        );
        registry.register(
            "ssh_admission_refusals",
            "Requests refused by session, state worker, or HTTP control capacity",
            refused.clone(),
        );
        registry.register(
            "ssh_upload_bytes",
            "Bytes in successfully completed uploads",
            uploaded.clone(),
        );
        registry.register(
            "ssh_download_bytes",
            "Bytes in successfully completed downloads",
            downloaded.clone(),
        );
        registry.register(
            "ssh_storage_reserved_bytes",
            "Full configured allowances reserved by transfer items and local input snapshots",
            storage_reserved.clone(),
        );
        registry.register(
            "ssh_storage_items",
            "Reserved transfer item slots, including in-flight and retained content",
            storage_items.clone(),
        );
        registry.register(
            "ssh_local_input_snapshots",
            "Local input snapshots retaining capacity",
            local_snapshots.clone(),
        );
        Self {
            registry,
            connection,
            audit,
            audit_failures,
            active,
            refused,
            uploaded,
            downloaded,
            storage_reserved,
            storage_items,
            local_snapshots,
        }
    }
}

impl Metrics {
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut output = String::new();
        encode(&mut output, &self.registry)?;
        Ok(output)
    }

    pub fn admission_refused(&self) {
        self.refused.inc();
    }

    pub fn storage_usage(&self, reserved_bytes: u64, items: u64, local_snapshots: u64) {
        self.storage_reserved.set(reserved_bytes);
        self.storage_items.set(items);
        self.local_snapshots.set(local_snapshots);
    }

    pub(crate) fn connection_setup(&self) -> Timer {
        Timer::new(self.connection.clone())
    }
    pub(crate) fn audit_ack(&self) -> Timer {
        Timer::new(self.audit.clone())
    }
    pub(crate) fn audit_failed(&self) {
        self.audit_failures.inc();
    }
    pub(crate) fn active_run(&self) -> Active {
        self.active.inc();
        Active(self.active.clone())
    }
    pub(crate) fn transfer_completed(&self, upload: bool, bytes: u64) {
        if upload {
            self.uploaded.inc_by(bytes);
        } else {
            self.downloaded.inc_by(bytes);
        }
    }
}

pub(crate) struct Timer {
    metric: Histogram,
    started: Instant,
}
impl Timer {
    fn new(metric: Histogram) -> Self {
        Self {
            metric,
            started: Instant::now(),
        }
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        self.metric.observe(self.started.elapsed().as_secs_f64());
    }
}

pub(crate) struct Active(Gauge);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.dec();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn measurements_have_fixed_series_and_release_active_capacity() {
        let metrics = Metrics::default();
        let active = metrics.active_run();
        assert_eq!(metrics.active.get(), 1);
        drop(active);
        assert_eq!(metrics.active.get(), 0);
        drop(metrics.connection_setup());
        drop(metrics.audit_ack());
        metrics.audit_failed();
        metrics.admission_refused();
        metrics.transfer_completed(true, 17);
        metrics.transfer_completed(false, 23);
        metrics.storage_usage(4096, 2, 1);
        let text = metrics.encode().unwrap();
        for expected in [
            "ssh_connection_setup_seconds_count 1",
            "ssh_audit_ack_seconds_count 1",
            "ssh_audit_failures_total 1",
            "ssh_admission_refusals_total 1",
            "ssh_upload_bytes_total 17",
            "ssh_download_bytes_total 23",
            "ssh_storage_reserved_bytes 4096",
            "ssh_active_runs 0",
        ] {
            assert!(text.contains(expected), "missing measurement: {expected}");
        }
        assert!(!text.contains("principal="));
        assert!(!text.contains("path="));
        assert!(!text.contains("command="));
    }
}
