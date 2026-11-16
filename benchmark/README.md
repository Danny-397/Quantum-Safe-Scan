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

18 files (10 positive, 8 negative/decoy) across 9 languages, 26 labeled findings:

| Configuration | TP | FP | FN | Precision | Recall | F1 |
|---|--:|--:|--:|--:|--:|--:|
| Naive line-regex baseline | 26 | 27 | 0 | 49.1% | 100% | 65.8% |
| **QuantumSafe (usage-aware)** | **26** | **0** | **0** | **100%** | **100%** | **100%** |

The usage-aware pass removes **27 false positives** — keyword mentions inside
docstrings, log/exception strings, trailing comments, and multi-line block
comments — without losing a true positive. Crucially, this now spans **all
supported languages**, not just Python: 13 of the removed false positives come
from Java, JavaScript, and Go decoys (`negative/notes.java`, `messages.js`,
`notes.go`). Genuine crypto usages whose algorithm is named *inside* a string
argument — e.g. Java's `getInstance("SHA-1")`, Node's
`createCipheriv("aes-128-gcm", …)` — are preserved by the string-argument
recovery pass, the cross-language analogue of the Python AST engine.

## Precision on real code (`precision_sample.py`)

The labeled corpus above was written for this project, so it is also the corpus
the scanner was tuned on. `precision_sample.py` measures precision where nobody
chose the code: it scans the same 37 PyPI packages as `realworld.py` (versions
pinned), draws **100 findings at random** (seed 2026) from all 5,679, and every
one is labeled by reading its source, with the reason recorded in
[`precision_labels.json`](precision_labels.json).

| Sample | Scanner | TP | FP | Precision | 95% CI |
|---|---|--:|--:|--:|--:|
| First, seed 2026, 100 of 5,679 findings | 0.3.1 | 93 | 7 | **93%** | 86% to 97% |
| Fresh, seed 2028, 100 of 8,909 findings | 0.3.2 | 95 | 5 | **95%** | 89% to 98% |

Four of the seven false positives were the same defect: the TLS 1.0 rule matched
`SSLv3` / `TLSv1` inside **disable** flags (`OP_NO_SSLv3`, `OP_NO_TLSv1`), which
are the mitigation, not exposure. The rule now requires the protocol name to start
its own token; regression tests cover both directions. The measurement above is
the scanner **before** that fix, reported as measured. Full table and every false
positive: [RESULTS-precision.md](RESULTS-precision.md).

The second row is a **fresh draw for 0.3.2**, from the same pinned packages, so it
measures the scanner after the recall fixes rather than re-scoring the sample whose
mistakes chose them. The recall fixes raised the pool from 5,679 findings to 8,909,
and precision held. Two things to read alongside it: three of the true positives are
the classical half of a post-quantum hybrid (X25519 or P-384 next to ML-KEM, named on
a nearby line), which the scanner's own hybrid rule says should not be reported, so
counting them as false positives gives **92% (85% to 96%)**; and the remaining false
positives are `dh` as a variable name (seen in the first sample too), telnet's `"EC"`
command, a GridFS `md5` attribute and a Sphinx stub. They are left unfixed so the
sample stays a measurement. Labels and reasons:
[`precision_current_labels.json`](precision_current_labels.json); full table:
[RESULTS-precision-current.md](RESULTS-precision-current.md).

```bash
python benchmark/precision_sample.py           # rescan, redraw (same seed, pinned versions)
python benchmark/precision_sample.py --score   # score the committed labels
python benchmark/precision_sample.py --current --score   # the fresh 0.3.2 sample
```

## Recall on real code (`recall_sample.py`)

A sample of findings can only say how many findings are wrong; it cannot see what
the scanner never reported. `recall_sample.py` measures the other half. It draws
random Python files that import a crypto-capable module from the same 37 pinned
packages (833 such files), labels **every** quantum-vulnerable usage in each one
by reading the file before the scanner is run on it, and counts a usage as found
when the scanner reports that family on one of its lines.

| Sample | Scanner | Usages | Found | Recall | 95% CI |
|---|---|--:|--:|--:|--:|
| First, seed 2026, 40 files | 0.3.1, blind | 28 | 19 | **68%** | 49% to 82% |
| Held-out, seed 2027, 40 other files | after the fixes below, blind | 26 | 23 | **88%** | 71% to 96% |

The first sample's nine misses were patterns the scanner had no rule for:
algorithm names inside identifiers (`RSAKey`, `ECDSAKey`, `X25519PrivateKey`;
Curve25519 / Curve448 were not matched at all) and string literals that *are* the
algorithm's wire name (`"ssh-rsa"`, `"rsa-sha2-256"`, `"kty": "RSA"`), which the
prose filter masked along with real prose. Both are fixed. Re-scoring the first
sample afterwards gives 93%, but that sample chose the fixes, so the held-out
sample, drawn and labeled afterwards from files the fixes never saw, is the number
to quote. Its three misses: a bytes literal listing several algorithms,
RSA selected through an imported constant (`SIGNATURE_RSA`), and MD5 reached
through a helper named `_md5sum`. Single DES (no scanner family) and code that
implements a curve without naming it remain out of reach of a pattern scanner.

**The new rules were checked for precision too.** Across the 37 packages they add
about 3,700 findings. A random 60 of them, read by hand, held 58 real usages and 2
false positives (a test function's name, and an RSA key type inside paramiko's
`disabled_algorithms`); both patterns are now filtered. The same sample showed
that `MLKEM768_X25519`-style post-quantum hybrids were being flagged as ECC, which
would tell users to replace the fix, so ECC on a line naming ML-KEM / Kyber is no
longer reported. Precision for the scanner with these rules is the fresh 0.3.2
sample above: 95%.

```bash
python benchmark/recall_sample.py --score              # first sample
python benchmark/recall_sample.py --holdout --score    # held-out sample
```

Results with every miss listed: [RESULTS-recall-holdout.md](RESULTS-recall-holdout.md),
[RESULTS-recall.md](RESULTS-recall.md).

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

Latest run (2026-10-28, scanner 0.3.1): **32 of 37** packages had findings across
**11,275** Python files — **5,609** findings (**4,236** HIGH-risk). Full results, per-package table, and
`file:line` examples in [RESULTS-realworld.md](RESULTS-realworld.md). Because these
are *unlabeled* real packages, results are reported as *discoveries* (each with
provenance), not scored against ground truth.

## Seeded recall benchmark (`seeded.py`)

The labeled corpus above is deliberately small, so on its own it measures
*precision* well but says little about *recall* at scale. `seeded.py` closes that
gap with a **mutation benchmark** whose ground truth is known **by
construction**: it embeds real quantum-vulnerable API calls (many idiomatic
variants per family, across 7 languages) into host files and asserts each is
detected, then embeds the *same algorithm name* only in a comment and a string
and asserts it is **not**.

```bash
python benchmark/seeded.py
```

Latest run: **50 seeded positive cases → 100% recall**, and **0 false positives**
across the 50 negative mutations (**100% mutation precision**). Per-language and
per-family recall tables, plus any misses, are written to
[RESULTS-seeded.md](RESULTS-seeded.md). This measures recall over API *variety*
(breadth), complementing the precision figure above; obfuscated wrapper chains
are a separate concern handled by the `--taint` data-flow engine.

## Honest limitations (what this benchmark does *not* prove)

This is a focused regression benchmark, not a large-scale field study. Real-world
caveats, stated plainly:

- **Labeled-corpus scale:** the precision corpus is 18 files / 26 findings. The
  seeded harness adds 50 constructed recall cases, but neither is a claim of 100%
  accuracy on arbitrary real-world code.
- **String/comment awareness spans all languages:** Python uses precise
  tokenizer-based masking; every other language uses a lexer-style state machine
  that blanks comment and string content. Go masks strings too, except on
  `import` lines (its import paths are the detection signal). Masked string usages
  are recovered by a targeted string-argument pass keyed on known crypto
  factories — precise, but narrower than a full parser, so an algorithm name
  passed through an *unrecognized* call can still be missed.
- **AST precision is still Python-only:** other languages remain pattern-based
  (regex + string-argument recovery), so deeply obfuscated wrappers may be missed
  (this is what the seeded harness's "misses" column and `--taint` address).

These are the genuine edges of a static pattern-based approach — see
`TECHNICAL_OVERVIEW.md` for how AST/Tree-sitter parsing would address them.
