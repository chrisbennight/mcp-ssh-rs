# Local performance measurements

These fixtures measure specific service costs without a real SSH target,
credentials, model, or external network. Run them separately from the ordinary
test suite so timing evidence is not confused with correctness assertions.

## Download scheduling and upload comparison

```sh
cargo test -p ssh-core --locked latency_benchmark -- --ignored --nocapture --test-threads=1
```

The fixture exchanges real SFTP packets over a local duplex stream. It compares
serial downloads with the bounded concurrent reader and exercises the unchanged
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

## Polling output and lock contention

```sh
cargo test -p ssh-core --locked polling_benchmark -- --ignored --nocapture --test-threads=1
```

The fixture compares the former eager output-copying operation with the current
running-status snapshot on small and full retained streams. It measures output
buffer allocation capacity and time while another thread contends for the record
mutex. The allocation figure is the actual capacity of the copied output
buffers, excluding common metadata and allocator overhead; it is not a claim of
zero total allocations. Lock-wait time is the competing thread's observed total
and depends on scheduling. Both paths use the same retained input and process.

Record the compiler, build profile, host load, and measured results with any
performance claim. A latency-controlled fixture supports conclusions about its
workload; it does not establish production WAN throughput or a universal speedup.
