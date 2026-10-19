# Contributing to Elytra

Thanks for helping. Elytra sits between coding agents and what they do, so changes are held to a high bar for correctness and clarity.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Security issues go through private vulnerability reporting (see [SECURITY.md](SECURITY.md)), never a public issue or pull request.
- Never include tokens, `~/.elytra` contents, real agent configs or customer data in issues, tests or screenshots.

## Development setup

```sh
python3 -m venv .venv && . .venv/bin/activate
(cd ui && npm ci && npm run build)
python -m pip install -e '.[dev]'
python -m pytest tests -q
```

Before opening a pull request, run:

```sh
python -m pytest tests -q
(cd ui && npm run build)
python scripts/qa_gate.py
```

## Ground rules

- **Never widen authority by accident.** Unknown, changed or suspicious tools must not run without review. Unrecognized shell commands classify as writes, never reads. Hooks never grant an agent more permission than it already had.
- **Credentials stay out of agent reach.** Owner and host tokens never enter an agent's or MCP server's environment, logs or events.
- **Tests come with behavior changes.** Classifier changes need cases in `tests/test_hooks.py`; runtime decisions need cases in `tests/test_runtime_service.py` or `tests/test_host_sessions.py`.
- **Claims match evidence.** Don't describe fixtures as measured attack rates or promise protection the code does not provide. See `docs/THREAT_MODEL.md`.
- **Match the surrounding code**: naming, comment density and the existing console design tokens.

## How changes land

This repository is the open-source part of Elytra. Maintainers also run a private repository for the hosted service, which mirrors this code. After your pull request is merged here, it is applied there unchanged and ships in the next release, credited to you. You may see a maintainer sync commit on `main` afterwards; that is the mirror catching up.

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
