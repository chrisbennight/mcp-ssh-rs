//! Service entrypoint.

use anyhow::Context as _;
use clap::Parser;
use ssh_core::config::Config;

#[derive(Debug, Parser)]
#[command(name = "mcp-ssh-rs", about = "MCP-mediated SSH access for AI agents")]
struct Args {
    /// Probe a running instance and exit non-zero if it is not serving.
    ///
    /// The container healthcheck runs this against itself rather than shipping
    /// a shell or curl in the runtime image, which keeps the image without a
    /// usable command interpreter.
    #[arg(long)]
    healthcheck: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = Config::from_env().context("reading configuration")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;

    if args.healthcheck {
        return runtime.block_on(healthcheck(&config));
    }

    tracing_subscriber::fmt()
        .json()
        // Audit entries are the only stdout producer. Diagnostics remain
        // independently useful on stderr without being able to split an audit
        // entry into an unparsable line.
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    runtime.block_on(ssh_server::serve(&config))
}

/// Asks the local instance whether it is serving.
async fn healthcheck(config: &Config) -> anyhow::Result<()> {
    let url = format!(
        "http://{}{}",
        ssh_server::probe_address(config.listen),
        ssh_server::HEALTH_PATH
    );
    // No proxy, ever. A default client discovers HTTP_PROXY and friends from
    // the environment, which would send this loopback probe out of the
    // container: the service would be healthy, the probe would fail, and the
    // request would have left the machine to establish it.
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("building the health probe client")?;
    let response = client
        .get(&url)
        .send()
        .await
        .context("probing the health endpoint")?;
    anyhow::ensure!(
        response.status().is_success(),
        "health endpoint returned {}",
        response.status()
    );
    Ok(())
}
