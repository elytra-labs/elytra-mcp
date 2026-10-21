# Decision quality: measured

How often Elytra interrupts everyday agent work, what it stops, and how fast it answers. Measured on 2026-10-20 against Elytra 0.4.0a3 (before) and 0.5.0a1 (after) on an M2 Pro MacBook Pro. Every number here comes from a script in this repository; run them yourself.

```sh
python -m benchmarks.classifier                 # labeled commands, decision by decision
python -m benchmarks.sessions --preset balanced # replayed agent sessions (also: cautious, autonomous)
python -m benchmarks.hook_latency               # wall clock per hook call
```

## Summary

| Measure | 0.4.0a3 | 0.5.0a1 |
| --- | --- | --- |
| Labeled commands (415): decisions matching intent | 71.0% | 100% |
| ... needless prompts (stricter than intended) | 124 | 0 |
| ... missed risks (looser than intended) | 117 | 0 |
| Held-out commands (164), first contact | not measured | 95.7% (9 needless, 5 missed), then fixed |
| Replayed sessions: interruptions per 100 everyday tool calls (Balanced) | 24.7 | 0.0 |
| Replayed sessions: attack sessions stopped (Balanced) | 14 of 14 | 14 of 14 |
| ... of which blocked outright, not just held | 5 | 6 |
| Held-out injection texts flagged, first contact | not measured | 7 of 10 (0 of 10 benign texts flagged), then fixed |
| Hook latency p50 / p95, file read | 116 / 187 ms | 38 / 42 ms |
| Hook latency p50 / p95, file edit | 110 / 150 ms | 38 / 43 ms |

"After" figures for the corpora and the injection set are in-sample: the classifier and the inspector were tuned against them. The first-contact figures are the honest estimate of how they generalize; the next release will be scored against new held-out sets written after this one.

## What was measured

**Labeled commands** (`benchmarks/commands/corpus.jsonl`). 415 shell commands an agent might run, each labeled with what it actually does: routine checks, installs, sensitive files, secret reads and sends, remote code, protected and working branches, deletes, history rewrites, and 25 obfuscated or indirect forms (wrappers, `bash -c`, `python -c`, base64 into a shell, command substitution). Each command goes through the real pipeline (hook classifier, Balanced preset, runtime) twice: in a clean session and after an uninspected untrusted read. The outcome (runs, asks, blocked) is compared with what the preset intends for that label. Two labels were reconciled after the fact for consistency with similar entries; both are marked in the file.

**Held-out commands** (`benchmarks/commands/heldout.jsonl`). 164 commands written in a different style (how agents chain commands in transcripts: `cd x &&`, workspace flags, monorepo runners) and scored once before any change. The 14 disagreements found (monorepo forms, PowerShell download-and-run, `npx rimraf`, deleting a protected branch) were then fixed.

**Replayed sessions** (`benchmarks/scenarios.py`). 16 everyday sessions (fix a bug, open a PR from an issue, bump a dependency, read docs, refactor, Rust and Go changes) and 14 attack sessions (a poisoned issue asking to send `.env`, a README injection asking for a force push, an MCP result asking for shell persistence, hidden page text asking for `curl | bash`, CI tampering, a typosquatted package, a secret committed and pushed, netcat exfiltration, an obfuscated delete, a git hook, a registry swap, an admin merge, a public gist of `.env`, and a plain-language page with no injection markers asking to post `.env`). Each step goes through the real hook handler and a live runtime, including the post-call inspection of what the tool returned. In everyday sessions a person is assumed to approve any prompt; in attack sessions the marked step must not run.

**Content inspection** (`benchmarks/content/heldout.json`). 10 injection texts and 10 benign texts that mention secrets, agents, force pushes and `curl`, written after the inspector and scored once.

**Latency.** The hook process spawned exactly as an agent spawns it, against a live runtime, 30 calls after warm-up. Python itself starts in about 12 ms of that.

## By preset

| Preset | Interruptions per 100 everyday calls | Attack sessions stopped |
| --- | --- | --- |
| Balanced | 0.0 | 14 of 14 |
| Cautious | 81.5 (every change asks, by design) | 14 of 14, and the limitation below is held too |
| Autonomous | 0.0 | 13 of 14: the typosquatted install runs, because Autonomous lets agents install freely and the forum post carries no injection markers |

## Known limitations

- **A plain-language page can still steer a local edit.** When content has no markers of an injection, Elytra's inspection finds nothing, the session counts as "untrusted, inspected, clean", and Balanced lets local edits run (sends stay blocked; unrecognized commands and installs still ask). The replayed limitation session (a page asking for a hard-coded master password) shows this. Review diffs before merging, or use Cautious.
- **The inspection is heuristic.** It looks for agent-directed instructions, concealment, secret requests, hidden text and known dangerous commands. Paraphrased or novel injections may pass; benign text that combines several of these signals may be flagged (which only makes Elytra stricter).
- **Classification is heuristic.** Commands Elytra cannot place are treated as unrecognized commands (a change, never a read). Scripts the agent writes and then runs are judged by the command that runs them, not by their contents.
- **Corpus scores are in-sample.** See the note under Summary.
