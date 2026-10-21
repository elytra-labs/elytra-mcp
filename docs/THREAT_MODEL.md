# Elytra threat model

Elytra is a local control plane for mediated MCP tool actions. Its security boundary is the supported runtime path; an attractive graph, a saved policy, or an installed wrapper alone does not prove that a call is protected.

## Actors and trust

The local operator is trusted to administer policies, approve actions, pin schemas, and configure connections. The run agent and content read from MCP servers cannot grant themselves operator permission. External source content, tool descriptions, arguments, and tool results may be malicious. Tool categorization expresses operator policy and uncertainty; metadata is not an authority.

An operator with access to the local administrative credential, database, process, or configuration can change protection. Elytra does not protect against that trusted operator, a compromised operating system, or another process running with equivalent access to its secrets. Keep the administrative token separate from credentials passed to an agent.

## Coverage

The explicit Python run integration supplies a run identity shared across its server calls. Policies and approval bindings use that identity. Generic host wrapping cannot reliably infer individual conversations from a shared MCP connection; any workspace-level coverage must be disclosed as such. A host without an explicit run boundary must not be advertised as conversation-isolated protection.

**Host sessions (0.4.0a1).** `elytra setup` wraps an agent host's stdio MCP servers (Claude Code, Cursor, Claude Desktop, Windsurf, VS Code) with a host credential. The bridge groups calls into a host session by the operating-system process that launched it: the host process identified by its PID and start time, skipping wrapper shells. Servers launched by one host process share a run, so untrusted context read through one server applies to sinks reached through another. This is host-process scope, not conversation isolation, and it is weaker than an explicit run:

- Claude Code starts one session per running `claude` process. Claude Desktop and Cursor typically start one session per app launch, so all conversations in that app share it. Sharing is conservative: context from one conversation can cause more prompts in another, never fewer.
- A host that launches servers through an intermediate long-lived process, or relaunches servers mid-conversation, may split or merge sessions differently.
- The host credential is stored in `~/.elytra/hosts/` (owner-only), never in the agent's own configuration (0.5.0a1; `elytra setup` moves it out of configurations written by earlier versions). It can open or resume host sessions, register tool metadata and report content-inspection results. It cannot classify tools, change policy, or approve calls. Anyone who can read that file can open sessions as that host; revoke it in the console or with `elytra uninstall`.
- A session run ends after 12 hours without calls, on revocation, or when the runtime restarts (the next call opens a fresh session). Host sessions use a longer approval window (default 10 minutes, at most 30) so an unattended agent can wait for a desktop notification to be answered.

**Agent hooks (0.4.0a1).** Coding agents act mostly through built-in tools. `elytra setup` installs PreToolUse and PostToolUse hooks in Claude Code (`~/.claude/settings.json`, also read by Grok), Grok (`~/.grok/hooks/`), Antigravity (`~/.gemini/config/hooks.json`) and Codex (a local plugin that the user trusts once). Each call is classified into a fixed Elytra action (`read_local`, `web_read`, `edit_files`, `run_command`, `send_data`, `delete_files`, `destroy_history`) and decided under the same host session as that agent's wrapped MCP servers. Limits:

- Shell classification is a heuristic over the command text. Obfuscation (encoded commands, scripts that perform network or destructive actions internally, aliases) can make a dangerous command look like `run_command` or a read. Unrecognized commands are treated as writes, so Balanced asks for them only after untrusted content; Cautious asks for every one.
- Self-protection (refusing agent access to `~/.elytra`, the local API, and the agent's own hook settings) is best-effort text matching. A process running as the same user can still read Elytra's files; the threat model's operator-trust boundary is unchanged.
- MCP tools seen only through hooks (for example remote connectors) have no schema, so schema pinning and drift detection do not apply. They are unknown until the operator classifies them.
- Codex cannot ask natively, and Antigravity does not report its permission mode, so for them a held action waits for an Elytra decision (desktop notification, console) until the approval window ends, then is denied. Claude Code and Grok in interactive modes show their own prompt with Elytra's reason; in bypass modes they wait like Codex.
- If the runtime is not running, hooks allow the action and say so, unless setup used `--fail-closed`. Hooks are configuration the user (or their agent, outside Elytra's coverage) can remove.

Catalog classification is a convenience, not a trust decision by Elytra. When the operator accepts a recognized server (matched by its launch package, not its display name), its listed tools receive the catalog's suggested categories on first registration. Unlisted tools, drifted or suspicious schemas, and unrecognized servers still require operator review. The catalog cannot know what a particular server build actually does.

Mediated calls can be denied, held for operator review, or dispatched. Source provenance and text matching support explanations; they do not establish intent or semantic causation. No tool is assumed harmless merely because its name resembles a reader or its arguments begin with `SELECT`. Classify unknown capabilities before allowing protected execution.

Elytra is not an OS, filesystem, or network sandbox. It cannot stop an agent from using an alternate client, direct API, shell, browser, unwrapped MCP server, or provider credential outside the mediated path. Destination systems must enforce their own identity and permissions. MCP traffic may contain data that secret pattern matching does not recognize.

## Authorization and execution integrity

An operator permission or approval must match the server, tool, canonical arguments, run, and policy version. Changes require a fresh decision. One-use approval cannot authorize a replay, another run, or substituted arguments. Denial, expiry, or cancellation must not dispatch a pending call. Schema drift requires review rather than silent repinning.

An action dispatched before a process crash may have succeeded even if no response was persisted. Prevent automatic redispatch of an uncertain operation and reconcile destination state. “Exactly once” is not a universal guarantee across arbitrary MCP servers; an idempotency mechanism at the destination is required for stronger guarantees.

## Local data and administrative API

Default retention is seven days for local operational metadata. Raw customer payloads should not be stored by default. Audit evidence should use identifiers, decisions, hashes, and redacted previews with bounded size. Retention is a minimization policy, not secure erasure from backups, filesystem snapshots, SQLite journals, or exported files.

Local administrative endpoints require a credential and reject untrusted browser origins and unauthorized writes. Loopback binding reduces exposure but is not itself authentication. Do not expose the local server publicly as a hosted team service.

Pattern-based redaction can miss transformed, partial, custom, or previously unknown secrets. Payload hashes may still reveal equality; even metadata can contain sensitive names. Operators should review retention and exported evidence for their environment.

## Evidence and release boundaries

See [evaluation methodology](evaluation/METHODOLOGY.md). Scripted fixtures do not establish general prompt-injection resistance, real agent attack success rates, enterprise readiness, or a population false-positive rate. Installation verification and passing tests are evidence for the specific tested path only. Customer adoption and purchasing evidence are tracked separately.

## Optional hosted workspaces (0.4.0a1)

Managed runtimes contact the cloud outbound over HTTPS and use a separate local database. Standalone historical data is not imported. Browser sessions use Supabase user identity; runtime credentials are scoped to one device and cannot exercise workspace administration. Workspace owner/admin decisions are delivered as signed, expiring envelopes. Ordinary notifications and unsigned database rows cannot authorize execution.

The cloud is a trusted policy administrator. A compromised cloud signing service or authorized workspace admin can grant permissions within the mediated path. A compromised machine administrator can bypass the runtime altogether. Five-minute cached management leases bound offline revocation delay; existing classified source reads may continue, while privileged dispatch fails without freshness. Restart requires a fresh lease. This is not immediate network-wide revocation or OS isolation.

One-use local claims and durable outcome receipts survive interrupted synchronization. Redelivered decisions cannot substitute arguments or repeat a claimed action. Cloud receipt state can lag local effects; the dashboard distinguishes approval from execution and uncertain outcomes. Reconnection does not replay operations. Retention and quota limits are independent of execution authority.

## Optional account link (0.4.0a2)

`elytra link` lets the owner decide held actions from another device. The local runtime keeps its own database, guardrails, classifications and hooks; nothing about local authority moves to the account. The link sends redacted summaries of pending approvals (agent label, `server.tool`, Elytra's reason, the already-redacted argument preview, and the exact binding), never tool results, tokens or full arguments. Approvals whose preview is too large to review safely stay local.

A remote decision applies only if its Ed25519 signature verifies against the key pinned at link time, it names this device and account, it is unexpired (at most 120 seconds and never past the held action's own expiry), and its binding (run, call, server, tool, arguments digest, schema and policy version) matches a still-pending approval. A command ID applies once. The first decision wins: an action already decided locally, expired, or invalidated by a policy or schema change is not affected. Losing the link never allows anything; the action keeps waiting for a local decision or expires. An unusable link credential does not stop the runtime from starting.

Within that boundary the account is trusted to answer for its owner. Anyone who controls the linked account (or the hosted signing key) can approve an action that is currently held on a linked machine, but cannot create permissions, approve anything not held, change guardrails or classifications, or alter what the action does. Signing in uses GitHub or Google identity only; protect that account as you would the machine. `elytra unlink` stops the link locally; removing the device in the dashboard revokes its credential.

## How decisions use what a session read (0.5.0a1)

**Sessions per conversation.** Hooks key a session by the agent's conversation id when the agent's hook payload includes one (Claude Code, Codex and Antigravity send one), so a new conversation or `/clear` starts clean. Wrapped MCP servers cannot tell conversations apart and keep using the host-process session. A conversation inherits what its process read directly (its MCP calls), and everything a conversation reads also counts for its process, so MCP sinks stay conservative. A conversation's session is cached owner-only in `~/.elytra/hosts/sessions/` for five minutes; a conversation resumed in a new agent process within that window may not yet inherit that new process's MCP reads.

**Taint levels.** A session's taint is the highest level among what it read: LOW (it read secrets), MEDIUM (untrusted content that Elytra inspected and found clean), HIGH (untrusted content Elytra could not inspect), CRITICAL (content that looks like instructions aimed at AI agents). Balanced lets local changes and pushes to working branches run at MEDIUM; unrecognized commands and installs ask; sends, downloaded code and history rewrites are blocked; changes through connected (MCP) tools ask. At HIGH, changes ask. At CRITICAL every change asks in every preset. After secrets are read, sends, pushes and new pull requests ask in every preset, and sending secret files is always blocked.

**Content inspection.** The hook (PostToolUse) and the MCP proxy inspect what a read returned before the agent acts on it, looking for instructions addressed to AI agents, attempts to override instructions or hide actions from the user, requests for secrets, hidden text and known dangerous commands. Results are never stored or sent; only a verdict and up to three short redacted snippets. A finding raises that source to CRITICAL and sends a desktop notification. A clean result lowers only that call's own untrusted source, only from HIGH to MEDIUM, and only once. This is heuristic: novel or paraphrased injections may pass (then Balanced still blocks sends and asks before unrecognized commands, installs, sensitive files and protected branches, but lets local edits run), and a process holding the host credential could report a false clean result. Measured detection and limitations are in `docs/evaluation/DECISIONS.md`.

**Trusted documentation.** Reads from a short built-in list of official documentation sites and package registries, plus sites the person adds with `elytra trust-domain` (stored in `~/.elytra/trusted-domains.json`), do not mark a session untrusted unless inspection flags their content. Entries match an exact host or a host and path prefix; subdomains are not included. Issues, pull requests, wikis, forums and gists are never on the built-in list.

**Upgrades.** On start, the runtime re-registers Elytra's built-in agent actions and re-applies the chosen preset's rules if they changed, without touching the person's own rules.

