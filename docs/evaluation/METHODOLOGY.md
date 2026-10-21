# Evaluation methodology

Elytra has two different evaluation paths. Neither uses a language model, a real customer account, or an agent that chooses tools.

## Scripted graph regression fixtures

Run `PYTHONPATH=src:. python -m benchmarks.runner` from a checkout. `run_full_benchmark(write_artifacts=False)` returns results without changing report files.

The legacy collection contains 50 scripted adversarial call pairs across ten server pairings and five text formats, plus 18 intended legitimate workflows. Variations reuse the same ten underlying actions; they are not 50 independent deployments. The runner passes a source response and a predetermined destination call into `RuntimeTaintGraph`. It observes the graph verdict, not whether an agent follows instructions, whether a destination executes, or whether a real system is compromised.

The legitimate collection includes external-read-to-write tasks. An interruption counts when the graph rejects the intended call. Task prose is not proof that a trusted operator granted permission. These fixtures illustrate the cost of broad topology restrictions; their interruption fraction is not a population false-positive estimate.

The previous “42/50 (84%) unprotected compromise” result was assigned by scenario index. It was never observed and is withdrawn. All baseline outcome fields are now null. Earlier reports quoting it must not be used for marketing, fundraising, or comparative claims.

Timing records nearest-rank p50, p95, and p99 over one source ingestion plus one graph decision per fixture. Reports include sample count, Python/platform, and UTF-8 payload size range. This measures graph code only; it excludes database, proxy, subprocess, model, network, and destination execution. It has no arbitrary universal latency threshold.

## Observed mock endpoint effects

`PYTHONPATH=src:. python -m benchmarks.measured_runner` runs a separate JSON-RPC mock endpoint subprocess. The endpoint records receipt and mutation effects in a temporary SQLite database. The same source, tool arguments, permission settings, and initial endpoint state are used in bypass and protected arms. Only the protected arm invokes the integrated runtime.

Each result includes the submitted request, runtime decision, response or error, destination mutation count before and after, and elapsed time. The bypass arm measures a scripted call without enforcement; it does not measure an unprotected agent's susceptibility. A prevented mutation means the endpoint did not apply that fixture's effect. It does not mean arbitrary attacks are prevented.

Protected cases cover missing permission, exact grants, changed arguments, unknown capability, concurrent run separation, approval binding and replay. A blocked call must cause zero destination mutations; a permitted call must produce the expected observed mutation. Compare actual responses and durable endpoint counters, not scenario-index expectations. Record failure outcomes instead of coercing a benchmark failure into a block result.

End-to-end timing includes local runtime dispatch and mock subprocess I/O. It excludes human approval wait and real provider latency. Report arm distributions and paired differences, payload sizes, warm-up count, sample count, and environment. A small local fixture set cannot establish service latency under load.

## Agent decision benchmarks (0.5.0a1)

`python -m benchmarks.classifier`, `python -m benchmarks.sessions` and `python -m benchmarks.hook_latency` measure the agent hooks: labeled shell commands, replayed agent sessions through the real hook handler and runtime, and hook wall-clock latency. They are scripted replays, not agent compromise measurements. Results, held-out first-contact scores and limitations are in `docs/evaluation/DECISIONS.md`.

## Evidence needed before protection claims

An agent-driven evaluation requires a pinned model/provider version, prompts, source content, tool schemas, agent/tool permissions, runtime policy, seeds where available, initial state, terminal effects, and complete redacted transcripts. Run the identical task in protected and bypass modes with fresh isolated state. Separate attack completion, legitimate task completion, interruption count, and evaluator uncertainty. Record unknown results explicitly. Provider credentials and customer authorization are not present in this repository; no such outcomes are claimed.

Publish evaluation date, commit, configuration, failures, and limitations with every result. Test new integration boundaries before adding them to the supported list. Customer interviews and the pilot provide adoption evidence; the fixture suite provides implementation evidence.
