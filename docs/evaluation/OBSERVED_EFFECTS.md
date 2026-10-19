# Scripted runtime observations

Generated: 2026-10-17T21:06:36.075158+00:00

Fixture pair checks passed: 53/53. Boundary checks passed: 9/9.

No language model or live external destination was used. No agent compromise rate is available.

## Timing

```json
{
  "environment": {
    "python": "3.13.5",
    "platform": "macOS-27.0.1-arm64-arm-64bit-Mach-O"
  },
  "arms": {
    "bypass": {
      "samples": 53,
      "p50_ms": 0.978,
      "p95_ms": 1.5006,
      "p99_ms": 2.9427
    },
    "protected": {
      "samples": 53,
      "p50_ms": 1.6629,
      "p95_ms": 3.6785,
      "p99_ms": 4.4681
    }
  },
  "paired_difference_ms": {
    "p50": 0.6747,
    "p95": 1.8769,
    "p99": 2.7485
  },
  "startup_included": false,
  "warmup_calls": 0,
  "human_wait_included": false,
  "payload_bytes_min": 109,
  "payload_bytes_max": 846
}
```

## Limitations

- Scripted calls, not agent-selected actions or real provider accounts.
- Direct RuntimeService dispatch with subprocess endpoints; HTTP/SDK transport is outside this harness.
- Temporary SQLite ledger effects only; no real shell, database, finance or external network operation.
- Bypass arm measures direct call effects, not agent compromise probability.
- Small sequential local sample; includes source + sink runtime/ledger/IPC cost but excludes process startup, setup, provider latency and human waiting.

Full recorded attempts, decisions and observed ledger effects: [observed_effects.json](observed_effects.json).
