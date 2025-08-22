# Ghost Protocol — Master Plan (14 weeks)

## North‑star
Ship a guarded‑retrieval system with cryptographically verifiable receipts and measurable leakage bounds (TV/MI/zCDP), with defenses against poisoned corpora and slow‑leak adversaries. All claims reproducible from code/logs.

## Architecture & repo mapping
- **S1 detector**: `sra/s1_detector.py` → substring/regex/Aho–Corasick hits, pressure score, timing/length buckets.
- **S2 templates**: `sra/s2_templates.py` → DFA membership (risk‑brief / status‑bullets / refusal), substring guard.
- **S3 budget**: `sra/budget_tracker.py` → zCDP ρ, ε(δ), TV bounds (Pinsker/BH), MI bits (ρ/ln2).
- **S4 audit**: `sra/audit_logger.py` + `demo/verify_audit.py` → hash‑chain + HKDF rotate.
- **RAG interposer**: `sra/rag_guardrail.py` (new) → fetch→scan→risk→mask→route.
- **Watcher**: `sra/watcher.py` (new) → KS on length/timing, logistic AUC, SPRT gate.
- **Policy glue**: `sra/policy_engine.py` → explicit routing + logs.
- **Attack harness**: `attacks/*`, driven via `scripts/run_evaluation.py`.

## The 10 needles (pass/fail)
1. Template zero‑leak: ≥3‑char substring leaks in TEMPLATE/REFUSAL: **0 / 10,000**.
2. Poison detection: Precision **≥0.90** / Recall **≥0.80**.
3. Two‑world indistinguishability: overall AUC **≤0.60**; TEMPLATE lane **≈0.50** (CI includes 0.5).
4. Receipt integrity: verify passes **100%** on ≥10^6 entries; first‑bad‑index detection works.
5. DP budget: ε(1e‑6) ≤ cap; MI bound ≤ **0.4 bits/session**.
6. Watchers: KS/discriminator trigger **auto‑downgrade**; FPR ≤ **5%**.
7. SPRT slow‑leak: FN ≤ **10%** at b=10; expected turns ≥ **0.9×** bound.
8. Perf (ex‑model): p95 control path **<50 ms**; e2e **<200 ms** @ 50–100 QPS (mock LLM ok).
9. CI reliability: main green; flake rate **<2%**; ≥ **80%** coverage for S2/S3/S4/verify.
10. Reproduce: `make reproduce` regenerates all figures ≤ **60 min** on a single VM.

## Datasets
- Benign: finance (10‑K/10‑Q), healthcare‑lite (PubMed), casual (Wikipedia/OSS).
- Poisons: synthetic PII + jailbreak text + secret markers (k‑bit positive controls).
- A/B: paired docs differing only by secret S.

## Math & receipts
- zCDP→ε(δ): `ε = ρ + 2√(ρ log(1/δ))`.
- TV bounds: Pinsker `√(½ KL)` vs. Bretagnolle–Huber `√(1−e^−KL)` → record tighter one.
- MI bound: `I ≤ ρ/ln2` (bits).
- Receipt schema per turn includes: turn, route, ρ_turn, ρ_session, ε(δ), KL, tv_bound + which inequality, mi_bits, len/time buckets, hash_prev/hash_curr/sig.

## MI estimation
- Primary: InfoNCE (K∈{64,128,256}, τ∈{0.05,0.1}), AdamW + cosine decay, early‑stopping, bootstrap (10×) 95% CI.
- Backup: classifier MI upper bound (logistic/MLP on world A vs B).
- Positive controls: injected k‑bit leaks must raise MI ≈ k within CI.

## Watcher/drift/fairness
- Drift metric: PSI or KS on S1 pressure + template acceptance rates per domain; PSI>0.25 → auto‑tighten policy.
- Auto‑downgrade to TEMPLATE when watcher thresholds breach; receipts log panic fields.

## Work packages (WPs)
- **WP1** S2 zero‑leak (DFA + AC) — 0/10k leaks; O(|out|) check.
- **WP2** Receipts v0.2 + verifier — TV/MI/zCDP fields + first‑bad‑index.
- **WP3** RAG interposer — P≥0.9 / R≥0.8; TEMPLATE lane 0 leaks.
- **WP4** Watcher — AUC≤0.60 overall; TEMPLATE≈0.50.
- **WP5** SPRT slow‑leak — FN≤10%; turns≥0.9× bound.
- **WP6** Perf & reproduce — <50 ms control path; one‑click figures.

## Timeline (weeks 1–14)
- W1 Contract + receipts hello; W2 S2 zero‑leak; W3 RAG interposer; W4 receipts v0.2 + demo.
- W5 DP summaries + budget; W6 watcher + A/B; W7 SPRT slow‑leak; W8 midterm freeze + UI.
- W9 budget‑burn detector; W10 perf; W11 monotonicity checker; W12 paper draft; W13 ablations & transparency; W14 final defense.

## Runs/outputs
- Header per JSONL: `{run_id, commit, dataset, policy, seed}`.
- Tree: `results/runs/<component>/<date>_<runid>.jsonl`, `results/plots/*.png`, `logs/audit/*.jsonl`.

## CI/CD & triage
- Workflows: ci (lint/tests), fuzz (nightly 100k), soak (weekly 60m).
- Failures attach artifacts; `scripts/debug_receipts.py` replays chains and prints first‑bad‑index.

## Compute & storage
- Local dev ≤1k; EC2 spot for sweeps; Codespaces for PR checks.
- S3 mirror of `results/`; Git LFS for plots; prune local >2 weeks.

## Risks & kill‑switches
- MI unstable → swap to classifier bound + annotate.
- ALLOW leaks → force TEMPLATE session; open bug; adjust via PR only.
- Drift PSI>0.25 → tighten policy; memo to advisor.
- DP overspend → block & downgrade; inspect ρ_turn.
- Perf regress → restrict padding to TEMPLATE; profile/revert.

---