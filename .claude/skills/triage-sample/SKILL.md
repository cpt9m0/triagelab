---
name: triage-sample
description: Run the full triage pipeline on a file and summarise the result. Use when asked to triage, analyse, or score a file in uploads/, fixtures/samples/, or any local path.
argument-hint: [path-to-sample]
arguments: sample_path
allowed-tools: Bash(uv run triagelab *), Bash(uv run python *), Read, Write
---

# Triage a sample

Run the pipeline, then interpret it. Do not re-implement analysis by reading bytes yourself -
the CLI already does the work deterministically.

## Steps

1. Run `uv run triagelab report $sample_path -o reports/`.
2. Read the generated `reports/<stem>.json`.
3. Summarise for the user in this shape, and nothing longer:
   - **Verdict line**: score, band, and the single strongest signal.
   - **Matched rules**: id, name, and the matched terms.
   - **What to do next**: one concrete suggestion (e.g. "hash lookup via the threat-intel
     subagent", "add a rule for the unmatched string X").
4. Offer to delegate a VirusTotal hash lookup to the `threat-intel` subagent. Do not
   perform the lookup inline - the point is to keep the API response out of this context.
   The free tier allows 4 lookups per minute, so do not fan this out across a directory.

## Rules

- Report only what the tool found. Do not infer capability, attribution, or intent from
  string matches - a string is evidence of a string, not of behaviour.
- The rules are substring matches over extracted ASCII. A packed or obfuscated binary will
  hide them, so a clean result is not evidence of safety. Say so when the score is low but
  entropy is high.
- Never edit files under `fixtures/samples/` or `uploads/`. They are inputs, not workspace.
- If the file is empty or unreadable, say so and stop.
