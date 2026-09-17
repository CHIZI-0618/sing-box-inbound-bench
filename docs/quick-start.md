# Quick start

This guide produces auditable raw data. It does not claim that one inbound is universally faster.

## 1. Build the tools

Build `inbound-bench` for the device under test (DUT) and for the benchmark server. Build sing-box
once with `with_ebpf`; use that exact binary for every non-raw subject. Runtime eBPF evidence uses
the built-in sing-box API and does not require `with_clash_api`.

```sh
go build -o build/inbound-bench ./cmd/inbound-bench
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o build/inbound-bench-android-arm64 ./cmd/inbound-bench
```

The sing-box build process is intentionally outside this repository. Save its full commit SHA,
dependency revisions and build tags with the submitted result.

## 2. Prepare the server

Use a wired server that is faster than the DUT path. TCP and UDP can listen on the same numeric port:

```sh
./inbound-bench tcp-server -listen 192.168.254.2:19090
./inbound-bench udp-server -listen 192.168.254.2:19090
```

Do not run the server through a VPN, proxy, NAT or firewall rule that changes the observed client
tuple. Confirm the raw baseline first.

## 3. Generate the matrix

```sh
./inbound-bench generate-matrix \
  --preset smoke \
  --output matrix-lan.json \
  --matrix-id device-link-date \
  --results results \
  --sing-box /absolute/path/to/sing-box \
  --target 192.168.254.2:19090 \
  --interface eth0 \
  --worker-uid 2000 \
  --udp-pps 100000
```

Start with `--preset smoke` (22 cases), continue with `core` (114) after the topology is proven, and
use `full` (168) only for the publishable run. `--subjects raw,ebpf-tc,ebpf-cgroup` and
`--workloads standby,tcp-rtt,udp-rtt,udp-rtt-unconnected` can create an explicit diagnostic subset.
Run a raw-only pilot before choosing `--udp-pps`. Generate separate 25%, 50% and 75% offered-load
matrices when comparing efficiency. Never silently edit a matrix after a run starts; resume rejects
configuration drift.

The generator gives every non-raw subject the same loopback sing-box API service so its idle memory
and CPU cost is not charged only to eBPF. It invokes `sing-box api ebpf` only for eBPF subjects and
only immediately before and after the timed workload. Connected and unconnected UDP are separate
workload keys and must not be merged.

## 4. Execute and resume

```sh
sudo ./inbound-bench matrix -config matrix-lan.json
```

On interruption, set `resume` to `true` in an otherwise identical matrix and run it again. A result
is skipped only when its JSON is complete and uses the current protocol version. Recreate summaries
without rerunning traffic:

```sh
./inbound-bench summarize -config matrix-lan.json
```

## 5. Decide whether results are publishable

Review `state.json`, `summary.json`, `summary.md`, every invalid repetition and all artifacts. Blocks
without a valid before/after raw control pair, or with more than 5% raw throughput drift, are excluded
from aggregation. A complete directory also needs:

- valid interception proof for every included repetition;
- `restore_verified=true` for every included repetition;
- zero corruption and no unexplained loss/drop/error;
- no eBPF attachment/state/recovery change or failure-counter increase between runtime snapshots;
- stable temperature/frequency conditions and a non-bottlenecked server;
- binary hashes and exact source/dependency revisions;
- no mixing of protocol versions, topologies, MTUs or offered loads.

Submit the full directory using the repository issue template, not a screenshot or hand-copied table.
