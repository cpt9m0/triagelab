# Custom rules

Drop-in rule files, one JSON object per file, using this schema:

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

Custom ids use the `TLC0N` prefix so they never collide with the built-in `TL0NN` range.
The `/new-rule` skill scaffolds files here.

**Nothing loads these yet.** `rules.load_custom_rules()` raises `NotImplementedError` - that
loader is the feature built live during the talk. `packer_artifacts.json` is here so the
loader has something real to pick up the moment it works: it matches `packed_blob.bin`,
whose score should move as soon as custom rules are merged in.
