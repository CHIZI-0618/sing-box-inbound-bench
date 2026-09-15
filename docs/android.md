# Android execution and recovery

Android runs require an already connected root ADB shell. The orchestrator does not enable USB
tethering, change Wi-Fi/mobile data, edit a default route, or manipulate KernelSU/Magisk modules.
Those are device-global choices with vendor-specific recovery behavior.

## Safe topology

Prefer a dedicated NCM/RNDIS `/30` link without Android tethering, DHCP, NAT or Windows ICS:

```text
Android: 192.168.254.1/30
Server:  192.168.254.2/30
```

Use the real interface name in the generated matrix and verify the eBPF TC diagnostics name that
same interface. A connected USB route alone does not guarantee that sing-box's default-interface
monitor selected it.

## Orchestrator configuration

Start from `configs/android-run.example.json`. The optional `service` object accepts argument arrays:

```json
{
  "service": {
    "status": ["/absolute/manager", "status"],
    "running_contains": "running",
    "stop": ["/absolute/manager", "stop"],
    "start": ["/absolute/manager", "start"]
  }
}
```

Use only commands you have manually verified for that manager. The runner reads status first, stops
only a service that was running, waits for it to stop, and restores/waits in a cancellation-independent
cleanup context. Omitting `service` means production service state is untouched; preflight will then
reject a concurrently running sing-box.

Run from the host:

```sh
./inbound-bench android-run -config configs/android-run.example.json
```

All remote files stay below `/data/local/tmp/sing-box/inbound-bench-<matrix-id>`. Unless
`keep_remote=true`, only this validated run-scoped directory is recursively removed. A cgroup subject
creates only its previously absent `/sys/fs/cgroup/sbi-<hash>` child and removes it with `rmdir` after
workers exit.

## Evidence and failure handling

The host receives the matrix directory even when some remote jobs are invalid. It also stores:

- `android-before.json` and `android-after.json`;
- remote combined stdout/stderr;
- structural route/rule/netfilter/link restore comparison.

Nftables handles and packet/byte counters are normalized out of restore comparison; structural
changes are not. Missing optional tools such as `nft` are recorded and skipped only for that snapshot
surface. If restore verification fails, do not reboot blindly: compare the two audit snapshots and the
per-repetition exact inverse commands first.

Real-device eBPF reports should include device model, Android build, kernel release, complete sing-box
startup log, `tools ebpf status` output and `/sys/fs/pstore/` after any reboot.
