# Scanner evaluation benchmark

A labeled benchmark that measures how well the QuantumSafe scanner actually works
— so "it detects vulnerable crypto" is a *measured* claim, not an assertion.

## Run it

```bash
pip install -e .
python benchmark/evaluate.py
```

## Method

- **Ground truth** (`labels.json`) is defined at **(file, detection-family)**
  granularity by hand.
- `benchmark/positive/` contains known-vulnerable code; `benchmark/negative/`
  contains safe code and **decoys** designed to trip a naive matcher: crypto names
  that appear only in **comments, docstrings, log messages, and exception
  strings**, and **word-boundary traps** (`md5sumLabel`, `rc4legacyName`,
  `dsaCount`) that must *not* match.
- `evaluate.py` runs the real scanner **twice** — once as a naive line-level regex
  and once with the string/comment-aware pass — compares detected vs. expected
  pairs, and reports precision / recall / F1 **plus the exact false positives and
  false negatives**, so the numbers are auditable and the improvement is measured.

## Results (current)

15 files (10 positive, 5 negative/decoy) across 9 languages, 26 labeled findings:

| Configuration | TP | FP | FN | Precision | Recall | F1 |
|---|--:|--:|--:|--:|--:|--:|
| Naive line-regex baseline | 26 | 14 | 0 | 65.0% | 100% | 78.8% |
| **QuantumSafe (usage-aware)** | **26** | **0** | **0** | **100%** | **100%** | **100%** |

The string/comment-aware pass removes **14 false positives** (keyword mentions
inside Python docstrings, log strings, and exception messages) without losing a
true positive. Comment-only mentions and word-boundary traps are handled by the
comment filter and anchored patterns.

## Real-world benchmark (`realworld.py`)

`evaluate.py` measures **precision/recall** on a small labeled corpus.
`realworld.py` answers the complementary question — *what does the scanner find in
real production code?* — by downloading the latest sdist of 37 popular PyPI
packages from the PyPI JSON API, extracting each (nothing built or executed), and
running the scanner:

```bash
python benchmark/realworld.py            # curated 37-package set
python benchmark/realworld.py --limit 10 # first N only
python benchmark/realworld.py flask paramiko  # explicit packages
```

Latest run: **32 of 37** packages had findings across **10,938** Python files —
**5,512** findings (**4,083** HIGH-risk). Full results, per-package table, and
`file:line` examples in [RESULTS-realworld.md](RESULTS-realworld.md). Because these
are *unlabeled* real packages, results are reported as *discoveries* (each with
provenance), not scored against ground truth.

## Honest limitations (what this benchmark does *not* prove)

This is a focused regression benchmark, not a large-scale field study. Real-world
caveats, stated plainly:

- **Small scale:** 15 files / 26 findings. It guards against regressions and
  demonstrates the approach; it is not a claim of 100% accuracy on arbitrary code.
- **String/comment awareness is Python-only:** Python masks string, docstring, and
  comment content (via `tokenize`) before the regex pass, so trailing comments and
  keywords-in-strings no longer false-positive there. Other languages still rely on
  the comment-line filter, so a crypto name inside a *string literal* in JS/Java/etc.
  can still be a false positive.
- **Regex outside Python:** only Python gets AST precision; other languages are
  regex-based, so unusual crypto wrappers can be missed (false negatives).

These are the genuine edges of a static pattern-based approach — see
`TECHNICAL_OVERVIEW.md` for how AST/Tree-sitter parsing would address them.
