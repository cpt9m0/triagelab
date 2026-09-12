# triagelab

## Code Review Rules

Before reviewing a pull request, read `.claude/agents/code-reviewer.md` and use it as the
canonical review rubric and output contract. The rules below add repository safety context.

### Safety boundaries

- Flag any change that executes, unpacks, downloads, or otherwise obtains code from a file
  being analyzed. triagelab performs static byte inspection only.
- Flag any path that sends a file to VirusTotal without an explicit human action through the
  dashboard consent checkbox or the CLI `--yes` flag. Hash lookups may send only the SHA256.
- Flag committed samples, generated reports, uploads, or secrets. Those artifacts must remain
  local and ignored by git.

### Project contracts

- `src/triagelab/` must use only the Python standard library. Third-party dependencies belong
  in `web/`.
- Every new detection rule must have a unique `TL0NN` ID, a category, a severity from 1 through
  5, and a focused test.
- Changes to scoring weights or bands must update the exact expected values in
  `tests/test_scoring.py` in the same pull request.

### Correctness focus

- Check scoring-band boundaries, regular-expression escaping, and empty or binary-file edge
  cases. Report only concrete defects introduced by the pull request, with a specific file and
  line and a concise explanation of the impact and fix.
