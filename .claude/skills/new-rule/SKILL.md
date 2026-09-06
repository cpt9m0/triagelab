---
name: new-rule
description: Scaffold a new custom detection rule as JSON in rules/custom/. Use when the user wants to add a detection, indicator, or pattern for triagelab to flag.
argument-hint: [rule-name]
arguments: rule_name
allowed-tools: Read, Write, Glob
---

# Scaffold a custom rule

Write a new rule file to `rules/custom/<slug>.json` using the schema below.

## Schema

```json
{
  "id": "TLC01",
  "name": "Human readable rule name",
  "category": "process-injection | persistence | network | obfuscation | recon | evasion",
  "severity": 3,
  "patterns": ["StringOne", "StringTwo"],
  "description": "One sentence on what this indicates."
}
```

## Steps

1. Read `src/triagelab/rules.py` and every existing file in `rules/custom/` to collect
   ids already in use. Custom rule ids use the `TLC0N` prefix so they never collide with
   the built-in `TL0NN` range.
2. Ask the user for patterns only if they have not supplied any. Otherwise infer sensible
   ones from the request.
3. Write the JSON file. Keep `patterns` to literal strings - the matcher escapes them, so
   regex metacharacters are matched literally.
4. Tell the user the rule is written **but not yet loaded**: `rules.load_custom_rules()`
   raises `NotImplementedError` until the custom rule engine is built.

## Note for the demo

This skill deliberately outruns the engine. Scaffolding a rule here and watching it have
no effect is the setup for the plan-mode segment, where the loader gets built live.
