# Elytra 0.3.0a1 verification

Observed locally on 2026-10-17, macOS arm64, Python 3.13.5. These observations apply to this alpha's mediated path, not arbitrary agents or unwrapped calls.

## Automated checks

- `PYTHONPATH=src:. python -m pytest tests -q`: **85 passed**. Includes runtime grants, cross-server run isolation, schema changes/removals, concurrent single-use claims, database ownership, interrupted outcomes, real HTTP/SDK/subprocess integration, and the actual CLI stdio bridge.
- `npm run build --prefix ui`: TypeScript and Vite build passed. Three.js is a separate lazy scene chunk, approximately 137 KB gzip; Vite reports its normal 500 KB uncompressed chunk warning.
- `npm audit --omit=dev`: zero reported production dependency advisories at the time checked. This is not a source audit or security certification.
- `python scripts/qa_gate.py`: all four bounded implementation checks passed. The observed-effects harness passed 53 paired scripted fixtures and 9 boundary checks. Full recorded timing and limitations are in [the effect report](evaluation/OBSERVED_EFFECTS.md).

## Distribution checks

Built both wheel and source distribution, then built another wheel from the source distribution. Installed in a clean virtual environment, copied `scripts/verify_installed_release.py` to a temporary directory, and ran it with isolated Python (`-I`) outside the checkout.

The installed check passed: distribution identity, package imported from site-packages, bundled UI assets, actual ephemeral HTTP routes, denied anonymous/incorrect credentials, rejected foreign-origin writes, authenticated empty runtime, packaged graph fixtures, four observed subprocess fixture pairs plus nine boundary checks, and installed CLI startup. No `PYTHONPATH` or editable install was used.

## Browser observations

- Public desktop homepage renders a real Three.js canvas; mobile, reduced motion, save-data, and unavailable WebGL use a static schematic.
- Keyboard navigation, animation pause/resume, documentation links, mobile navigation, and viewport overflow were checked.
- Public documentation, install, security, and illustrative demo routes make no local runtime API requests. Public `/app/` does not mount the private console.
- Local browser pairing works on initial navigation and in an existing tab, and removes the one-time code from the address bar.
- A harmless SQLite fixture had **zero destination mutations while pending**. After clicking **Approve exact call**, the supported Python transport completed and the destination had **one mutation**. An earlier review expired without dispatch. Test fixtures and live user startup data are separate.

## Remaining product evidence

No customer interviews, paid pilots, production deployment of customer tools, independent security audit, hosted team accounts, SSO, streamable HTTP destinations, or measured live-agent compromise rate are claimed.
