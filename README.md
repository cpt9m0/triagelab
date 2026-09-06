# triagelab

A small static-triage tool used as the live demo project for the Claude training talk
**"Building Smarter Workflows."** Upload a file, and it extracts entropy/strings/hashes,
matches indicator rules, scores risk 0-100, writes a report, and can check the hash
against VirusTotal.

The tool is real and works on real binaries. Its purpose, though, is to be a repository
that exercises every rung of the workflow maturity ladder from the talk.

## The repo ships empty on purpose

No samples, no reports. You add files during the demo, which is the point: the audience
watches real binaries get triaged rather than staring at fixtures someone prepared earlier.
`fixtures/samples/`, `uploads/` and `reports/` are gitignored.

## What is real, and what is not

| Layer | Status |
| --- | --- |
| Entropy, SHA256/MD5, string extraction | **Real.** Standard techniques, correctly implemented. Verify against `strings(1)` and an independent entropy calculation any time. |
| VirusTotal lookups | **Real.** Live public API, your key, your quota. |
| Indicator rules | **Real technique, naive implementation.** Plain substring matching over extracted ASCII - no PE/ELF parsing, no imports table, no disassembly. A genuinely packed binary hides these strings, so this would miss it. |
| Risk score weights | **Invented for the demo.** Deterministic and test-pinned, but not calibrated against any corpus. |

Worth saying out loud to a security-literate audience: a string match is evidence of a
string, not of behaviour. Scanning a real system binary live is a good way to make that
point honestly.

## Setup

```bash
uv sync --extra web                    # install, including the dashboard
cp .env.example .env                   # then paste your key into .env
uv run pytest -q                       # 45 tests, all green
```

Get a free API key at <https://www.virustotal.com/gui/my-apikey>. The dashboard works
without one; VirusTotal panels just report `no_key` instead.

### VirusTotal free tier

The public API allows **4 lookups/minute, 500/day, 15.5k/month**, and must not be used in
business workflows or commercial products. triagelab enforces those limits client-side so a
live demo cannot blow the quota:

- every response is cached in `.vt_cache/` by hash - repeat lookups cost nothing
- a rolling window blocks a fifth call inside any 60 seconds, with a clear "try again in Ns"
- a daily counter stops at 500
- **only the SHA256 is sent.** The file itself never leaves your machine.

## Submitting a file VirusTotal has never seen

A `not_found` result means nobody has ever submitted that file - common for installers,
freshly built binaries, and per-download stubs. It is not evidence of safety.

You can upload the file so VirusTotal analyses it, but understand what that does:

> **Uploading publishes the file.** Anything submitted to VirusTotal becomes retrievable
> by their Intelligence subscribers. This is a well-known data-exfiltration path for
> proprietary code and confidential documents. It cannot be withdrawn.

So the upload is never automatic. It happens only when you ask for it:

- **Dashboard**: a `not_found` panel grows an "Upload file for analysis" button behind a
  consent checkbox. After upload the panel shows the queued analysis and a "Check analysis"
  button; when it completes, the full report replaces it.
- **CLI**: `uv run triagelab submit <file> --yes`, optionally `--wait 3` to poll for the
  verdict. Without `--yes` it refuses and explains why.
- **In code**: `intel.submit_file(path, confirm=True)`. Without `confirm` it returns an
  error and never touches the network, so no test or agent can publish a file by accident.

Submissions count against the same free-tier quota as lookups (4/min, 500/day), and
analysis usually completes in well under a minute.

## Usage

```bash
uv run triagelab scan <file>                    # summary to stdout
uv run triagelab scan <file> --vt               # ... plus a VirusTotal lookup
uv run triagelab report <file> -o reports/      # write JSON + Markdown
uv run triagelab batch <dir>                    # triage a whole directory
uv run triagelab submit <file> --yes            # PUBLISH the file to VirusTotal
uv run triagelab submit <file> --yes --wait 3   # ... and poll for the verdict
uv run --extra web uvicorn web.app:app --port 8000   # dashboard on :8000
```

The dashboard's upload box accepts multiple files at once. Uploaded files are written to
`uploads/`, read as bytes, and **never executed**. Each report page has a "Look up this
hash" button so you spend quota deliberately rather than on every page view.

## Demo map: one artifact per rung

| Rung | Artifact in this repo | What the audience sees |
| --- | --- | --- |
| 1 Context | `CLAUDE.md` | `/context` shows it loaded; conventions Claude follows unprompted |
| 2 Plan mode | the deliberate gap (below) | explore -> plan -> implement -> commit, live |
| 3 Skills | `.claude/skills/triage-sample/`, `new-rule/` | one command runs a whole pipeline |
| 4 Subagents | `.claude/agents/threat-intel.md`, `code-reviewer.md` | VT lookup happens in a separate context; only a summary returns |
| 5 Hooks | `.claude/settings.json` + `scripts/hook_*.py` | a blocked edit, an auto-run suite, a refused "I'm done" |
| 6 MCP | `vt_mcp_server/server.py`, `.mcp.json` | `/mcp` shows it connected; the subagent calls a real API through it |
| 7 Scale | `batch`, `claude -p`, worktrees | many files at once; two parallel sessions |

## The deliberate gap (this is the plan-mode demo)

`rules.load_custom_rules()` raises `NotImplementedError`. The `/new-rule` skill already
writes rule JSON into `rules/custom/`, and **nothing reads it yet**. `tests/test_rules.py`
pins that gap with a test asserting the `NotImplementedError`.

That is the feature you build on stage:

1. `Shift+Tab` into plan mode. Ask: *"read rules.py and the new-rule skill, then plan how to
   load custom rules from rules/custom/*.json and merge them with the built-ins."*
2. Review the plan, `Ctrl+G` to edit it, approve.
3. Let Claude implement. The PostToolUse hook runs the suite after each edit, and the
   gap-guarding test forces Claude to update the contract rather than quietly leave it.
4. Ask the `code-reviewer` subagent to review the diff before committing.

`rules/custom/packer_artifacts.json` is already there, matching `UPX0`/`UPX1`. Upload a
packed binary before the demo and its score will move the moment the loader works.

To rehearse again: `git checkout -- .`

## Stage directions

**Before you start.** Have 3-5 files ready to upload: a benign system binary
(`notepad.exe`, `/bin/ls`), something packed if you have it, and a text file. Do one
practice upload so the dashboard is warm, then delete `reports/` and `uploads/` contents.

**Rung 1 - Context.** Run `/context`, point at the CLAUDE.md line. Then ask Claude to add a
rule: it independently gives it a `TL0NN` id, a severity, and a test, because CLAUDE.md
says so and nobody typed that into the prompt.

**Rung 3 - Skills.** `/triage-sample uploads/<file>` - one command, whole pipeline,
structured summary. Then `/new-rule` to scaffold a rule and show it has no effect yet.

**Rung 4 - Subagents.** *"Triage that file, then have the threat-intel subagent tell me what
VirusTotal knows about the hash."* Show `/context` before and after: the API round trip and
the raw response never entered the main window - six lines came back.

**Rung 5 - Hooks.** Three moments, in order:
- Ask Claude to *"edit a file under fixtures/samples/"*. Blocked by policy, with the message
  telling it to change the generator instead. Guidance-vs-guarantee, live.
- Edit anything under `src/` and let the PostToolUse hook run the suite automatically.
- Break something, then tell Claude it's done. The Stop hook refuses and hands the failure
  back. Evidence, not assertion.

**Rung 6 - MCP.** `/mcp` shows `virustotal` connected. Open `vt_mcp_server/server.py`: a
complete MCP server against a real API, one file, standard library, ~150 lines.

**Rung 7 - Scale.**
```bash
uv run triagelab batch uploads/
claude -p "triage every file in uploads/ and list only the high and critical ones" \
  --output-format json
claude --worktree rule-engine
```

**Honesty beat (recommended).** Scan a real system binary live - `uv run triagelab scan
/bin/ls` or `notepad.exe` - to prove the analysis isn't theatre, then name the limitation:
string matching finds strings, and a packed sample would hide them.

## Troubleshooting: `failed to locate pyvenv.cfg`

If `uv run` reports `failed to locate pyvenv.cfg`, the `.venv` in this folder is partial:
uv populated `Scripts/` and `Lib/` but never wrote `pyvenv.cfg`, so the console-script
shims have no interpreter to find.

This happens when the project folder is shared with another system - a synced folder, a
network drive, or a Linux VM mount - because venv creation is not atomic across that layer.

Fix, in PowerShell:

```powershell
Remove-Item -Recurse -Force .venv
uv sync --extra web
```

If it recurs, keep the environment outside the shared folder entirely:

```powershell
# once, for this shell
$env:UV_PROJECT_ENVIRONMENT = "$env:USERPROFILE\.venvs\triagelab"

# or permanently
setx UV_PROJECT_ENVIRONMENT "$env:USERPROFILE\.venvs\triagelab"

uv sync --extra web
uv run --extra web uvicorn web.app:app --reload --port 8000
```

Everything else in the repo is path-independent, so nothing breaks by relocating the venv.
Do this before the talk rather than during it: a rebuild takes a few seconds, but not while
an audience watches.

## Windows notes

Hook commands in `.claude/settings.json` call `python`. If your PATH exposes the launcher as
`py`, change the three `command` values. The hook scripts are standard-library only and
handle both `\` and `/` path separators.

## Reset between rehearsals

```bash
uv run python scripts/demo_reset.py   # clears reports/, flags a dirty tree
git checkout -- .                     # discard the live-built feature
```

Delete `.vt_cache/` only if you want to prove a lookup is live - it costs quota to refill.

## Layout

```
CLAUDE.md                  project context and conventions (rung 1)
.env / .env.example        VT_API_KEY - .env is gitignored
.claude/settings.json      three hooks (rung 5)
.claude/skills/            triage-sample, new-rule (rung 3)
.claude/agents/            threat-intel, code-reviewer (rung 4)
.mcp.json                  registers the VirusTotal MCP server (rung 6)
vt_mcp_server/             one-file stdio MCP server over the VT public API
src/triagelab/             features, rules, scoring, report, intel, config, cli (stdlib only)
web/                       FastAPI dashboard: upload + report browser + VT panel
uploads/                   your demo files land here (gitignored, ships empty)
reports/                   generated output (gitignored, ships empty)
fixtures/generate_samples.py   optional synthetic samples if you want an offline fallback
scripts/                   hook implementations and demo_reset
tests/                     45 tests, including the one guarding the live-demo gap
```
