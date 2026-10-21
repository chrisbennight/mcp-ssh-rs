# Local performance measurements

These fixtures measure specific service costs without a real SSH target,
credentials, model, or external network. Run them separately from the ordinary
test suite so timing evidence is not confused with correctness assertions.

## Download scheduling and upload comparison

```sh
cargo test -p ssh-core --locked latency_benchmark -- --ignored --nocapture --test-threads=1
```

The fixture exchanges real SFTP packets over a local duplex stream. It compares
serial downloads with bounded windows of 8, 32, and 64 requests and exercises the unchanged
dependency upload writer. Cases vary file size, response delay, and consumer
delay. The response delays model round-trip latency; the consumer delay models
storage backpressure. This isolates scheduling and does not measure SSH
encryption, a real network, filesystem performance, or whole-service throughput.

Each JSON record includes elapsed time, throughput, process CPU time, cumulative
process peak RSS where Linux exposes it, outstanding request count, and content
digest. Download records include the scheduled-byte budget. That budget excludes
protocol framing, SSH buffers, and the fixture's source data. Peak RSS includes
the test process and fixture and is cumulative across cases, not an isolated
allocation measurement for one transfer. Cancellation has a separate record.
Uploads validate every written byte against the expected offset and report the
matching source digest.

Ordinary regression tests separately cover ordered binary delivery, short and
invalid responses, disconnection, backpressure, cancellation, worker failure,
and transfer outcomes. Performance measurements are not correctness gates, and
no wall-clock speed threshold is enforced on shared builders.

## Disk transfer batching

```sh
cargo test -p ssh-server --locked disk_batch_benchmark -- --ignored --nocapture --test-threads=1
```

This fixture compares the former per-chunk copying writer with bounded write
batches that return their buffer for reuse. Both paths receive the same small
binary stream and check the resulting size and digest. It measures local disk
scheduling and copying, including filesystem caching, without SSH or network
traffic. Ordinary tests cover fragmented input, a final partial batch, byte
limits, independent readers, and storage failure. Timing is not a CI threshold.

## Polling output and lock contention

```sh
cargo test -p ssh-core --locked polling_benchmark -- --ignored --nocapture --test-threads=1
```

The fixture compares the former eager output-copying operation with the current
running-status snapshot and completed snapshots that share retained bytes, on
small and full retained streams. It measures output buffer allocation capacity
and time while another thread contends for the record
mutex. The allocation figure is the actual capacity of the copied output
buffers, excluding shared byte storage, common metadata, and allocator overhead;
it is not a claim of zero total allocations. Lock-wait time is the competing
thread's observed total and depends on scheduling. All paths use the same
retained input and process.

Record the compiler, build profile, host load, and measured results with any
performance claim. A latency-controlled fixture supports conclusions about its
workload; it does not establish production WAN throughput or a universal speedup.

## Audit acknowledgement responsiveness

```sh
cargo test -p ssh-core --locked audit_latency_benchmark -- --ignored --nocapture --test-threads=1
```

The fixture compares a synchronous ledger call with the asynchronous state
worker on a single-thread Tokio runtime. A fake required sink delays each write
by 100 ms. It records acknowledgement duration and when an unrelated async
heartbeat can run. There is no timing threshold.

An example run used Rust 1.98.1, unoptimized tests on Linux, and three samples
per path. Host load was not controlled. Observed ranges, in milliseconds:

| Path | Acknowledgement | Unrelated heartbeat |
| --- | ---: | ---: |
| Synchronous ledger call | 110.131–110.269 | 110.355–110.456 |
| Asynchronous state worker | 103.153–111.358 | 0.094–0.351 |

The acknowledgement still waits for the sink. This result measures runtime
responsiveness under the injected delay; it does not measure production sink,
SSH, or network latency. Ledger access still serializes behind a pending write.
