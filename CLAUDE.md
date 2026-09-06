# triagelab

Static triage toolkit, used as the demo project for the "Building Smarter Workflows"
Claude training. It scans files the presenter supplies at demo time, scores them, and
optionally checks the hash against VirusTotal.

## Safety rules (non-negotiable)

- **Static analysis only.** This tool reads bytes. It never executes, unpacks, or shells
  out to anything it inspects, and it must not grow a feature that does.
- **No samples in git.** `fixtures/samples/`, `uploads/` and `reports/` are gitignored and
  ship empty. Files analysed during a demo are the presenter's own and stay local.
- **Lookups are hash-only.** `intel.lookup()` sends the SHA256 and nothing else.
- **Uploads publish.** `intel.submit_file()` sends the file itself to VirusTotal, where
  their Intelligence subscribers can download it. It cannot be undone. It therefore
  requires `confirm=True`, and that argument is passed in exactly two places: the
  dashboard's consent-checkbox form, and the CLI's `--yes` flag. Both are human actions.
  - **Never call `submit_file` yourself.** Not in a test, not in a smoke check, not to
    "verify the integration", not on the user's behalf without them asking for that
    specific file. Tests monkeypatch `_request_json`; a real call inside the test suite
    is a bug, and `tests/test_intel.py` has a fixture that fails the run if one happens.
  - Never submit anything proprietary, confidential, or personal. When in doubt, ask.
- **No secrets in git.** The key lives in `.env`, which is gitignored. `.env.example` holds
  the placeholder. Never write a real key into any tracked file.

## Build and test

- Install: `uv sync` (add `--extra web` for the dashboard)
- If `uv run` fails with `failed to locate pyvenv.cfg`, the `.venv` is partial: delete it
  and re-run `uv sync`. See the troubleshooting section in README.md.
- Test: `uv run pytest -q` (must pass before any change is considered done)
- Lint: `uv run ruff check src tests web`
- Triage one file: `uv run triagelab scan <path>` (add `--vt` for a VirusTotal lookup)
- Triage a directory: `uv run triagelab batch <dir>`
- Dashboard: `uv run --extra web uvicorn web.app:app --reload --port 8000`
- Optional synthetic samples: `uv run python fixtures/generate_samples.py`

## Layout

- `src/triagelab/features.py` - entropy, strings, hashes.
- `src/triagelab/rules.py` - indicator rules. Rule IDs are `TL0NN` and must stay unique.
- `src/triagelab/scoring.py` - deterministic 0-100 risk score. Tests pin exact numbers.
- `src/triagelab/report.py` - report dict, Markdown rendering, file output, VT attachment.
- `src/triagelab/intel.py` - VirusTotal client: cache-first, quota-aware, stdlib only.
- `src/triagelab/config.py` - `.env` loading. Real environment variables win.
- `src/triagelab/cli.py` - argparse entry point (`scan`, `report`, `batch`).
- `web/app.py` - FastAPI dashboard: upload, report browser, on-demand VT lookup.
- `vt_mcp_server/server.py` - one-file stdio MCP server exposing `lookup_hash`, `vt_quota`.

## Conventions

- The core package under `src/` uses the standard library only. `urllib` is fine;
  `requests` is not. Third-party imports belong in `web/`.
- Every new rule needs: a unique `TL0NN` id, a category, a severity 1-5, and a test.
- Scoring changes must update `tests/test_scoring.py` in the same change - the exact
  numbers are the contract, not an implementation detail.
- VirusTotal discipline: cache-first, never retry a rate-limited lookup in a loop, and
  never raise the client-side limits above the free tier (4/min, 500/day).
- Report a detection ratio as engine agreement, not as ground truth. Low-count detections
  are frequently false positives.
- Reports in `reports/` are generated output. Never hand-edit them.
- Never write into `fixtures/samples/` directly; change the generator and re-run it.
  A PreToolUse hook enforces this.

# Compact instructions

When compacting, keep: the current task, failing test output, and any decision about rule
semantics, scoring weights, or VT quota handling. Drop: raw file listings, full string
dumps from triaged samples, and verbose pytest passes.
