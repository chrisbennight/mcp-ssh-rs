//! Measure discovery JSON bytes without connecting to a target or model.

use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transfers = ssh_server::transfer::Transfers::new(
        Arc::new(ssh_core::clock::SystemClock::new()?),
        "https://example.invalid",
    )?;
    let mut measurements = Vec::new();
    for (mode, catalog) in [
        ("commands", ssh_server::tools::catalog()),
        (
            "http_files",
            ssh_server::tools::catalog_with_files(Some(&transfers)),
        ),
    ] {
        measurements.push(serde_json::json!({
            "mode": mode,
            "tools": catalog.tools.len(),
            "catalog_json_bytes": serde_json::to_vec(&catalog)?.len(),
        }));
    }
    serde_json::to_writer_pretty(std::io::stdout().lock(), &measurements)?;
    Ok(())
}
