# Changelog

## 0.4.0a2 · Unreleased

- Approve from your phone. `elytra link` links this machine to a free account (GitHub or Google sign-in); held actions then appear in the hosted dashboard, ready to approve or deny from any device. The local runtime, its database, guardrails and hooks stay authoritative: the link uploads redacted summaries of pending approvals only, never tool results or credentials, and applies a decision only when its Ed25519 signature, device, account, expiry and exact binding (run, call, tool, arguments digest, schema and policy version) all match a still-pending action. The first decision wins, a lost link never allows anything, and an unusable link never stops local protection from starting. `elytra unlink` stops it; `elytra status` and the console's Guardrails page show it. Team-managed mode (`elytra login`) is unchanged.
- New interface palette. The green tint is gone: neutrals are neutral, allowed actions are quiet, and color marks only what needs a person (amber for held, red for blocked). Every text color passes measured contrast targets, decorative greys are no longer used for content, corner radii follow one scale, and all native dropdowns are replaced with a themed, keyboard-accessible control.
- Open source at https://github.com/elytra-labs/elytra-mcp. The local runtime, hooks, CLI, console and site are licensed Apache-2.0 from this release (0.4.0a1 was MIT). The Elytra name and logo are covered by TRADEMARKS.md. The hosted service is not part of the open-source repository.

## 0.4.0a1 · 2026-10-18

- Publish on PyPI as `elytra-mcp`: `pipx install elytra-mcp`, then `elytra setup`. The `mirage` CLI alias is removed (it collides with the separate `mirage-ci` package); `elytra` and `mirage-mcp` remain. Add `elytra service restart`.
- The public site leads with the PyPI install, and offers hosted sign-in only once the deployment's backend responds. The hero no longer flashes its static drawing before the WebGL scene loads.
- Check coding agents' own actions, not only MCP tools. `elytra setup` installs PreToolUse/PostToolUse hooks for Claude Code, Codex (local plugin), Grok and Antigravity. Shell commands, file edits and web access are classified into fixed Elytra actions and decided by the same guardrails and host sessions as MCP calls; remote connectors seen through hooks wait for classification. Verified with real Claude Code, Codex, Grok and Antigravity runs (a held `rm -rf` or `git push --force` did not run). Antigravity's MCP config and Codex/Grok MCP servers (through their own CLIs) are also supported.
- Add personal guardrails for agent hosts. `elytra setup` runs the runtime as a background service, finds Claude Code, Cursor, Claude Desktop, Windsurf and VS Code MCP configurations, wraps their local stdio servers with a backup, accepts catalog classifications for recognized servers, and applies a guardrail preset (Balanced, Cautious, Autonomous). `elytra uninstall`, `status`, `service` and `open` complete the lifecycle.
- Add host sessions: calls from servers launched by one agent host process share a run, authenticated by a narrow host credential that cannot classify, change policy, or approve. Host sessions use a 10-minute approval window by default and reopen automatically after a runtime restart.
- Add category-aware policies (runtime and hosted validator), a tool catalog for common MCP servers, desktop notifications for held calls, and a Guardrails page in the local console.
- Add a shared management API with Vercel deployment and Supabase tenant isolation, OAuth-capable dashboard, enrollment, memberships, bounded usage, versioned policies, and exact approvals.
- Add an optional outbound Python connector with pinned Ed25519 verification, managed local administration, fresh leases, replay-safe claims, and durable receipts.
- Add real PostgreSQL concurrency checks and Worker/Python integration, plus actual Supabase Auth/RLS and browser-to-local-fixture verification.
- Upgrade frontend build tools to patched Vite 8 and React plugin 6.
- Redesign the public site around the control plane. The hero is a WebGL wind tunnel: tool calls are streamlines flowing over a delta wing in the logo's planform, calls that cross it leave in sage, and one write is held in amber at a raised elevon. The workflow section is scroll-pinned and shows an illustrative console moving through one run: explicit run, allowed read, held write, exact-call review, and a single dispatch with replay refused. Display headlines use Newsreader; interface and body text stay Geist. Scenes are labeled illustrative, pause offscreen, adapt quality, and fall back to a static drawing without WebGL or with data saving. Adds Lenis inertial scrolling (pinned 1.3.26).
- Align the local console with the site palette. Add approval search, live expiry countdowns and stated reasons for disabled decisions, activity session filtering, exact `server.tool` labels, hosted tool and activity filters, quota meters, valid policy templates, a mobile workspace menu, and client-side public page navigation.

Production backend credentials and GitHub/Google provider configuration remain pending; no live public hosted signup is claimed. The existing local release remains supported. No paid plans or add-ons were enabled.

## 0.3.0a1 · 2026-10-17

- Add a shared authenticated loopback runtime, explicit Python run integration, and tools-only stdio bridge.
- Require operator classification, exact permissions, single-use dispatch claims, and durable uncertain outcomes.
- Add a paired local console with empty live startup data and a separate public website with documentation and an illustrative demo.
- Add an original Three.js execution boundary illustration with accessible static fallbacks.
- Bundle frontend and fixture resources in the Python wheel and verify installation away from the source checkout.

- Withdraw the previous assigned 84% unprotected compromise baseline. Legacy result fields now report an unavailable baseline explicitly.
- Label graph evaluations as scripted verdict fixtures and add legitimate external-read-to-write workflows that reveal workflow interruptions.
- Add a recorded mock endpoint evaluation method, customer discovery guide, pilot protocol, threat model, and support/security reporting instructions.

This is an early access alpha. No completed customer pilot or independent security validation is claimed. See evaluation reports for the exact code path and environment measured.
