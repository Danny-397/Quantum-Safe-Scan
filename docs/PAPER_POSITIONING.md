# Paper positioning & novelty analysis (read before writing anything)

Prepared as a pre-writing reconnaissance so the paper's novelty survives contact
with the literature. **Bottom line: do not write "I built a quantum-vulnerable
crypto scanner." Write "I built the first reusable, multi-language *benchmark* for
quantum-readiness scanners, and used it to measure the field."** The scanner is the
apparatus; the benchmark and the measurement are the contribution.

---

## 1. The landscape (why the obvious framing is already taken)

The "scan code → flag RSA/ECC → score risk → recommend NIST PQC → emit CBOM"
concept is **not novel as of 2026.** Prior art that would be cited against it:

**Existing quantum-readiness scanners (direct competitors):**
- `open-quantum-secure` — 14+ languages, CycloneDX 1.7 CBOM, CNSA 2.0 checks. https://github.com/jimbo111/open-quantum-secure
- CryptoScan / QRAMM Toolkit (CSNP) — source + config + dependency scan, migration-readiness score. https://github.com/csnp/cryptoscan
- IBM CBOM / CBOMkit + Sonar Cryptography Plugin — cryptographic asset discovery → CBOM. https://github.com/IBM/CBOM
- PostQ / PostQuant — TLS/endpoint readiness scanners. https://postq.dev/

**The closest academic prior art (this is the dangerous one):**
- Shaw, A. *Quantum-Safe Code Auditing: LLM-Assisted Static Analysis and Quantum-Aware
  Risk Scoring for Post-Quantum Cryptography Migration.* arXiv:2604.00560.
  → scanner + quantum-aware risk scoring + tool comparison. Nearly our framing.
- QED-Lite: *Lightweight Detection of Quantum-Vulnerable ELF Binaries.* IACR ePrint 2026/660.

**Standards / policy grounding (cite, don't claim):**
- NIST FIPS 203 / 204 / 205 (ML-KEM / ML-DSA / SLH-DSA), NIST IR 8547 (PQC transition).
- CycloneDX CBOM 1.6 spec; White House NSM-10 / OMB M-23-02 migration mandates.

**Verdict:** as a *tool*, QuantumSafe is a competent re-entry into a populated field.
A reviewer's first comment on a "tool" paper would be "how is this different from
open-quantum-secure or Shaw 2026?" — and we don't have a strong answer at the tool level.

---

## 2. The genuine gap (what to actually claim)

Every **labeled benchmark** in this neighborhood measures a *different task*:

| Benchmark | Task | Not our task because… |
|---|---|---|
| CryptoAPI-Bench, MASC | Crypto **misuse** (bad IV, ECB, static key) — Java only | Misuse ≠ quantum-vulnerability; RSA-2048 done *correctly* is still HIGH for us |
| CryptoGuard / CogniCrypt eval sets | Crypto misuse (Java) | Same; single-language |
| CryptoScope / LLM-CLVA | Crypto **logic** vulns (CVE/CTF) | Different task entirely |
| QED-Lite | Quantum-vulnerable **binaries** (ELF) | Binaries, not source; single dimension |

**No published, reusable, multi-language, source-level benchmark exists for the
*quantum-vulnerability detection* task, with a measured head-to-head of the actual
scanners people use.** That is the defensible contribution, and it is exactly what
`benchmark/` was built to do.

### The claim, precisely worded
> Existing quantum-readiness scanners ship without shared ground truth, so their
> accuracy is asserted, not measured, and they cannot be compared. We release
> **QVaultBench** (rename as you like): a labeled, multi-language corpus for
> quantum-vulnerable cryptography detection — with adversarial decoys (crypto names
> in comments/strings/logs) and a seeded-mutation set that provides ground-truth
> recall — and we use it to run the first measured head-to-head of open-source
> quantum-readiness scanners.

Three things make this genuinely publishable and hard to wave away:
1. **A reusable public dataset** (most tool papers never release one).
2. **Multi-language** (11 languages vs. the Java-only misuse benchmarks).
3. **A head-to-head across real tools**, not just "ours vs. a naive regex."

---

## 3. What you already have vs. what the pivot needs

**Already done (this is why the pivot is realistic):**
- Labeled corpus with adversarial decoys → `benchmark/labels.json`, `benchmark/RESULTS.md`
- Seeded-mutation ground-truth recall set → `benchmark/RESULTS-seeded.md`
- A comparison harness that *runs other tools* on shared ground truth → `benchmark/comparison.py`, `COMPARISON.md`
- Ecosystem-scale exposure study (37 PyPI pkgs, 10,938 files) → `benchmark/RESULTS-realworld.md`

**The pivot's new work (this is the honest cost):**
1. **Add the real competitors to `comparison.py`.** Right now it compares against
   `bandit`. Install and wire in the *quantum-specific* tools — `open-quantum-secure`,
   `cryptoscan` (CSNP), semgrep crypto rulesets — so the head-to-head is against the
   actual field, not a generic SAST tool. **This is the make-or-break step;** a
   benchmark that only beats bandit is not interesting.
2. **Grow + freeze the corpus.** 26 (file, family) pairs is thin for a benchmark
   paper. Aim for ~60–100 labeled instances across the 11 languages, version-tag it,
   and publish it (Zenodo DOI or a tagged GitHub release) so it's citable/reusable.
3. **Position honestly against Shaw 2026.** Read it in full; state plainly what it did
   (LLM-assisted detection + comparison) and what it did *not* (release a reusable,
   multi-language benchmark). Your differentiator is the **artifact**, not the scanner.
4. **Report inter-tool agreement and disagreement**, not just "we win." The
   interesting science is *where and why* tools disagree on the same ground truth.

---

## 4. Paper skeleton (maps existing assets → sections)

1. **Abstract** — quantum-readiness scanners exist but are unmeasured; we release the
   first reusable multi-language benchmark and measure the field.
2. **Introduction** — HNDL threat, the migration-inventory problem, "you can't measure
   what you can't benchmark." Contribution bullets: dataset, protocol, head-to-head.
3. **Related work** — (a) quantum-readiness tools [open-quantum-secure, CryptoScan,
   CBOMkit, Shaw 2026, QED-Lite]; (b) crypto-misuse detection + its benchmarks
   [CryptoGuard, CogniCrypt, CryptoAPI-Bench] — explain why that task ≠ this task;
   (c) standards [FIPS 203–205, IR 8547]. **This section is where the paper is won or lost.**
4. **The detection task, defined** — what counts as a quantum-vulnerable finding
   (family-level, not misuse); the risk tiers. ← from `docs/WHITEPAPER.md` §1–2, §5.
5. **QVaultBench** — corpus design, adversarial decoys, the seeded-mutation recall set,
   labeling protocol, languages. ← `benchmark/RESULTS.md`, `RESULTS-seeded.md`.
6. **Evaluation** — head-to-head of N scanners: precision/recall/F1 per tool, per
   language; agreement analysis; the naive-regex baseline as the floor. ← `comparison.py`.
7. **Ecosystem study** — the 37-package exposure result as a real-world application. ← `RESULTS-realworld.md`.
8. **Limitations** — family-level (not misuse) detection; decoy design choices;
   survivorship in the ecosystem study; single-author labeling (mitigate: publish labels).
9. **Conclusion + released artifacts** (dataset DOI, harness).

---

## 5. Honest cost/benefit for admissions

- **Upside:** a released benchmark is a *real, citable, reusable* contribution — the
  strongest kind of student paper, and it plays to QuantumSafe's actual strength.
- **Cost:** the pivot is ~3–5 focused weeks (competitor wiring + corpus expansion +
  writing + a genuine related-work section). Higher than the "polish the whitepaper"
  fantasy, because the novelty bar is real.
- **Venue reality without a mentor:** arXiv needs an endorsement (skipped), so the
  realistic targets are **SSRN / a credible peer-reviewed HS journal (JEI)**, plus the
  Zenodo dataset DOI for citability. A workshop is possible but timing-dependent.
- **The honest fork:** if 3–5 weeks on a benchmark paper isn't appealing, the paper is
  *not* your highest-ROI move anymore — essays + one competitive result would be. This
  memo exists so that's an informed choice, not a discovery made mid-draft.
