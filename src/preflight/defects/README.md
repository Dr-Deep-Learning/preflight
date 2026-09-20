# Defect catalog

One YAML file per defect. Filenames match the lowercase ID (`sec-001.yaml`).
IDs are permanent: never renumber or reuse one, because eval labels reference them.
Retire a defect by setting `status: deprecated`.

## Fields

| Field | Required | Purpose |
|---|---|---|
| `id` | yes | `<CATEGORY>-<NNN>`, e.g. `AUTH-002` |
| `title` | yes | One-line name |
| `category` | yes | `secrets`, `access-control`, `injection`, `payments`, `cost`, `config` |
| `severity` | yes | `critical`, `high`, `medium`, `low` |
| `detector` | yes | `rule` (deterministic only), `llm` (LLM only), `both` (rule pre-filter, LLM confirms) |
| `status` | yes | `active`, `experimental`, `deprecated` |
| `applies_to` | yes | `stacks` and file `globs` used to decide which files to send |
| `cwe` | no | CWE numbers |
| `description` | yes | What the defect is. Fed to the LLM prompt |
| `why_ai_apps` | yes | Why AI coding tools tend to produce it |
| `bad_example` / `good_example` | yes | Few-shot examples for the LLM and seeds for eval cases |
| `false_positive_notes` | yes | Look-alikes that are safe. Fed to the prompt and used to write hard negatives |
| `references` | no | Docs links |

## Detector choice

Use `rule` when a pattern is unambiguous (a leaked key format, `allow write: if true`).
Use `llm` when the judgment needs context across lines or files (does this route check ownership?).
Use `both` when a cheap rule can find candidates and the LLM decides whether each is real.
This keeps LLM cost proportional to suspicious code rather than to repo size.
