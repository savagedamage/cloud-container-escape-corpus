# Contributing

Thanks for contributing. The corpus is dual-readership by design — keep that
in mind for every change.

## The two contracts

1. **Human contract:** every technique has a playbook in `corpus/techniques/`
   with frontmatter + Summary / Prerequisites / Attack path / PoC sketch /
   Detection / Mitigation / References.
2. **Machine contract:** `corpus/taxonomy/taxonomy.json` mirrors the playbook
   frontmatter; `corpus/detection/index.yaml` maps rules to techniques; JSON
   Schemas in `schemas/` define all structured output.

**Every change must update both layers.** After any edit run:

```bash
escape-corpus validate     # cross-check taxonomy/index/rules/schemas
python -m pytest tests/    # unit suite
```

## Adding a technique

1. Create `corpus/techniques/CE-0NN-<slug>.md` with the standard sections
2. Add the entry to `corpus/taxonomy/taxonomy.json` (id, name, category,
   MITRE, risk, prerequisites, guide path, detection rule ids)
3. Add `CE-0NN` to `corpus/index.yaml` and `corpus/INDEX.md`
4. Add at least one Sigma or Falco rule under `corpus/detection/` and index it
5. Run `escape-corpus validate` until clean

## Adding a detection rule

1. One rule per file, named `sigma-NNN-slug.yml` / `falco-NNN-slug.yaml`
2. Declare `detects:` technique IDs in `corpus/detection/index.yaml`
3. Reference the rule id from the technique's `detection_rule_ids` in
   `taxonomy.json`

## Tool changes

- Keep `escape_corpus/` importable and pip-installable; no import-time side
  effects
- Outputs must stay schema-compatible (`schemas/*.schema.json`); bump
  `schema_version` in `taxonomy.json` if you change structure
- Unit tests live in `tests/` — extend `tests/test_tools.py` for new checks

## Style

- PoC sketches stay at mechanics level; no turnkey exploits
- MITRE IDs in machine data use canonical `T####(.###)` form
- Playbook frontmatter must match the taxonomy entry exactly (validate catches drift)
