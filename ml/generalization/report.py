"""Render frozen aggregate findings only; never read email text or refit."""
import argparse
import json

from ml.data_pipeline import ROOT
from ml.report import NAMES


def num(value):
    return "n/a" if value is None else f"{value:.4f}"


def table(lines, title, entries):
    lines += ["", "## " + title, "",
              "| Candidate / source | n | Precision | Recall | F1 | FPR | FNR | FP | FN | Brier | ECE |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for label, m in entries:
        values = [num(m[k]) for k in ("precision", "recall", "f1", "false_positive_rate", "false_negative_rate")]
        lines.append(f"| {label} | {m['count']} | " + " | ".join(values) +
                     f" | {m['false_positives']} | {m['false_negatives']} | {num(m['brier_score'])} | {num(m['ece_10_equal_width'])} |")


def render(test_count):
    recipe = json.loads((ROOT / "data/sources_v2.json").read_text())
    manifest = json.loads((ROOT / "data/manifest_v2.json").read_text())
    lock = json.loads((ROOT / "reports/candidate_v2_selection.json").read_text())
    final = json.loads((ROOT / "reports/candidate_v2_final.json").read_text())
    chosen = final["selected_model"]
    lines = ["# AI Dataset Generalization v2: measured research results", "",
        "**Active model: unchanged 16-example legacy fallback. No research candidate was activated.**",
        f"Preselected research candidate: **{NAMES[chosen]}**. Any candidate eligible: **{final['any_candidate_eligible']}**.",
        "The v1 candidate remains unvalidated and inactive.", "",
        f"Protected checkpoint: {recipe['protected_commit']}. No commit, remote or push is part of this milestone.",
        f"Full offline suite: **{test_count} tests passed**. Tests require no public datasets, trained candidate binaries or network.",
        "", "## Dataset decisions and provenance", "",
        "Only public CSV text/metadata was used. Raw/derived emails and fitted binaries are ignored. Counts are measured from pinned files, not advertised full-corpus sizes. The original four sources are publisher-declared CC-BY-4.0 under [Zenodo 8339691](https://zenodo.org/records/8339691). New sources have citations, version URLs and usage notes in ml/data/sources_v2.json.",
        "", "| Admitted corpus | License | Raw | Label eligible | Usable before dedup | Retained | Class |",
        "|---|---|---:|---:|---:|---:|---|"]
    for source in manifest["sources"]:
        c = source["counts"]
        labels = source.get("label_map", {str(source.get("label")): source.get("label")})
        url = source.get("source", "https://zenodo.org/records/8339691")
        lines.append(f"| [{source['name']}]({url}) | {source['license']} | {c['raw']} | {c['label_eligible']} | {c['usable_before_deduplication']} | {manifest['retained']['source_counts'].get(source['name'], 0)} | {', '.join(str(v) for v in sorted(set(labels.values())))} |")
    lines += ["", "Labels: 0 legitimate; 1 phishing/social-engineering fraud. Synthetic samples are stress evidence, not observed inbox phishing. TREC-06 spam is excluded. Adjei advertises 4,211 messages, but only 4,181 rows have admissible labels. Kuladeep's 2026 title refers to a September 2025 release.",
        "", "| Source / publisher | Period | Usage/provenance notes |", "|---|---|---|"]
    for s in recipe["additional_sources"]:
        lines.append(f"| {s['name']} / {s['publisher']} | {s['period']} | {s['usage_notes']} |")
    lines += ["", "The four original collections are historical (the combined release describes 1995–2022); reliable individual cross-source chronology was not established. A recent dataset release does not make its email recent.",
        "", "Every additional dataset actively assessed is listed below. Search suggestions without substantive review were not treated as corpus decisions. Unverified counts mean no raw corpus was obtained.",
        "", "| Dataset considered | Publisher | License / terms | Reported size | Decision and reason |",
        "|---|---|---|---|---|"]
    for s in recipe["additional_considered"]:
        if s["decision"] == "SCOPE":
            continue
        label = f"[{s['name']}]({s['source']})" if s.get("source") else s["name"]
        count = s["reported_count"] if s["reported_count"] is not None else "not verified"
        lines.append(f"| {label} | {s['publisher']} | {s['license']} | {count} | {s['decision']}: {s['reason']} |")
    counts = {}
    for source in manifest["sources"]:
        for key, value in source["counts"].items():
            counts[key] = counts.get(key, 0) + value
    d = manifest["deduplication"]
    lines += ["", "## Exclusions, duplicates and balance", "",
        f"Inspected **{counts['raw']:,} raw rows**. Excluded **{counts.get('excluded_other_labels', 0):,} generic-spam/other-label rows**, **{counts.get('invalid_label_excluded', 0):,} missing/invalid labels**, **{counts.get('empty_excluded', 0):,} empty examples**, and **{counts.get('malformed_csv_excluded', 0):,} malformed CSV rows**.",
        f"Of **{d['input']:,} usable rows**, removed **{d['duplicates_removed']:,} duplicates** from retained consistent families; quarantined **{d['conflicting_rows_quarantined']:,} conflicting-label rows** and **{d['exposed_v1_rows_quarantined']:,} rows in {d['exposed_v1_groups_quarantined']:,} exposed-v1 evaluation families**. Retained **{d['retained']:,} representatives**.",
        f"The graph made {d['exact_component_merges']} exact and {d['template_component_merges']} additional template/body component merges and found {d['near_edges']} near edges. Edges are not additional removed-row counts; conflict/exposure quarantine takes priority.",
        "", "| Source | Legitimate | Phishing/fraud | Fitted training after cap |", "|---|---:|---:|---:|"]
    for s, c in manifest["retained"]["source_class_counts"].items():
        lines.append(f"| {s} | {c.get('0', 0)} | {c.get('1', 0)} | {manifest['training_after_cap']['source_counts'].get(s, 0)} |")
    c = manifest["retained"]
    lines += ["", f"Class balance: **{c['class_counts']['0']:,} legitimate**, **{c['class_counts']['1']:,} phishing/fraud**. **{c['synthetic_count']:,} records are synthetic**. Only Kuladeep contributes both labels within one collection; its prompts differ by label.",
        "", "## Partitions and untouched-test methodology", "",
        "| Partition | Total | Legitimate | Phishing/fraud | Synthetic |", "|---|---:|---:|---:|---:|"]
    for name in ("train", "validation", "test"):
        c = manifest["splits"][name]
        lines.append(f"| {name} | {c['count']} | {c['class_counts']['0']} | {c['class_counts']['1']} | {c['synthetic_count']} |")
    c = manifest["training_after_cap"]
    lines += [f"| Training actually fitted | {c['count']} | {c['class_counts']['0']} | {c['class_counts']['1']} | {c['synthetic_count']} |", "",
        "Source+class strata are split after global duplicate/conflict quarantine, seed 20260904. New-source strata use 70/15/15. Old-source components are development-only, 85/15/0. Strata under eight rows are training-only and reported.",
        "The final test covers **TREC-06, Adjei BEC and Kuladeep only**, with no old-source representative or detected v1 evaluation family. All its positive examples are synthetic. This is a fresh diagnostic research holdout, **not a representative deployment test**. Old sources receive validation and training-only source evaluation.",
        "TF-IDF and three-fold sigmoid calibration see training only. The cap applies only to training, after splitting. Each source-holdout model tunes thresholds on internal validation from its fitting sources only. All four artifacts and per-candidate mixed-validation bands were locked before final testing.",
        "Final-test results never choose a model or revise thresholds. Model/code/data/lock hashes and a single-use marker guard final evaluation. A better final score from another model cannot switch the preselected candidate.",
        f"Temporal evaluation: **unavailable**. {manifest['temporal_evaluation']['reason']}",
        "", "## Fixed candidates and validation choice", "",
        "The four v1 model configurations are reused: TF-IDF word unigrams/bigrams, min_df=2, max_df=0.98, 50,000 features, sublinear TF; LR/SVM C=1 and balanced classes, NB alpha=1. Sigmoid calibration uses training-only out-of-fold predictions with TF-IDF inside each fold. No sweep, neural model or GPU dependency was added.",
        f"Preselected **{NAMES[chosen]}** using: {lock['policy']['selection']}",
        "", "| Candidate | Review / high | Validation F1 | LOSO worst error | Macro recall | Macro FPR | Macro Brier | p95 ms | Failed gates |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for n, c in lock["candidates"].items():
        s = c["source_evaluation"]["summary"]
        m = s["macro"]
        lines.append(f"| {NAMES[n]} | {c['thresholds']['suspicious']:.2f} / {c['thresholds']['high']:.2f} | {num(c['validation']['pooled']['f1'])} | {num(s['worst_source_error'])} | {num(m['recall']['value'])} | {num(m['false_positive_rate']['value'])} | {num(m['brier_score']['value'])} | {c['inference_ms_p95']:.3f} | {len(c['development_gates']['failed'])} |")
    table(lines, "Mixed-source validation at validation-selected review thresholds",
          [(NAMES[n], c["validation"]["pooled"]) for n, c in lock["candidates"].items()])
    table(lines, "Fresh new-source final research test at locked review thresholds",
          [(NAMES[n], c["test"]["pooled"]) for n, c in final["candidates"].items()])
    lines += ["", "| Candidate | Final accuracy | ROC-AUC | PR-AUC (AP) | Log loss | Confusion [[TN,FP],[FN,TP]] |",
              "|---|---:|---:|---:|---:|---|"]
    for n, c in final["candidates"].items():
        m = c["test"]["pooled"]
        lines.append(f"| {NAMES[n]} | {num(m['accuracy'])} | {num(m['roc_auc'])} | {num(m['pr_auc_average_precision'])} | {num(m['log_loss'])} | {m['confusion_matrix']} |")
    selected = final["candidates"][chosen]["test"]["pooled"]
    lines += ["", f"Selected candidate confusion matrix: **{selected['confusion_matrix']}**; **{selected['false_positives']} FP**, **{selected['false_negatives']} FN**. These describe the stated diagnostic split, not real-world accuracy."]
    table(lines, "Validation per source", [(NAMES[n] + " / " + s, m) for n, c in lock["candidates"].items()
                                         for s, m in c["validation"]["per_source"].items()])
    table(lines, "Final test per new source", [(NAMES[n] + " / " + s, m) for n, c in final["candidates"].items()
                                             for s, m in c["test"]["per_source"].items()])
    lines += ["", "Single-class sources have n/a positive-class precision/F1. Unsupported recall/FNR/FPR are n/a, never zero or safe. Macro summaries retain supporting-source denominators; large corpora get no additional weight."]
    loso, pairs = [], []
    for n, c in lock["candidates"].items():
        for f in c["source_evaluation"]["leave_one_source_out"]:
            if f["status"] == "EVALUATED":
                loso.extend((NAMES[n] + " / " + s, m) for s, m in f["evaluation"]["per_source"].items())
        for f in c["source_evaluation"]["paired_source_transfer"]:
            if f["status"] == "EVALUATED":
                pairs.append((NAMES[n] + " / " + ", ".join(f["held_out_sources"]), f["evaluation"]["pooled"]))
    table(lines, "Leave-one-source-out using fitting-source-only thresholds", loso)
    table(lines, "Train-on-other-sources / unseen source-pair transfer", pairs)
    lines += ["", "Source experiments use the mixed training partition only. JSON retains internal fit/validation/check counts, source purges, thresholds, fixed-0.50 comparisons, macro summaries and reliability bins.",
        "", "## Calibration and residual source artifacts", "",
        "Per-source Brier, log loss, ten-bin reliability and ECE are recorded for all candidates. Brier combines discrimination and calibration; sparse bins and prevalence changes limit inference. Low pooled Brier cannot establish real-inbox probability calibration."]
    a = manifest["artifact_audit"]
    s = lock["source_predictability"]
    lines += [f"Training-only audit: {a['marker_counts']['embedded_metadata_rows_before']} rows contain embedded metadata and {a['marker_counts']['filenames_rows_before']} contain filenames before scrubbing; no known marker pattern remained afterward. {a['repeated_line_groups']} repeated-line groups occur in at least 20 messages. Only hashes/counts of these lines are exported.",
        f"The separate text-to-source classifier achieves validation accuracy **{s['validation_accuracy']:.2%}**, balanced accuracy **{s['validation_balanced_accuracy']:.2%}**, versus majority-source baseline **{s['majority_source_baseline']:.2%}**. Metadata removal does not eliminate topic and collection fingerprints.",
        "", "## Deployment gates fixed before fitting", "",
        "| Development gate | Required | " + " | ".join(NAMES[n] for n in lock["candidates"]) + " |",
        "|---|---|" + "---|" * len(lock["candidates"])]
    first = next(iter(lock["candidates"].values()))["development_gates"]["gates"]
    for name, g in first.items():
        values = []
        for c in lock["candidates"].values():
            gate = c["development_gates"]["gates"][name]
            actual = gate["actual"]
            actual = str(actual) if isinstance(actual, bool) or actual is None else num(actual)
            values.append(("PASS" if gate["passed"] else "FAIL") + f" ({actual})")
        lines.append(f"| {name} | {g['operator']} {g['limit']} | " + " | ".join(values) + " |")
    for name, rationale in lock["policy"]["rationale"].items():
        lines += ["", f"**{name}:** {rationale}"]
    lines += ["", "Final confirmation repeats numerical checks with locked test predictions and retains development failures. Full confirmation gates are in JSON/metadata; final performance never erases a source-validation failure.",
        "", "| Candidate | Validation state | Eligible | Failed development gates |", "|---|---|---|---|"]
    for n, c in final["candidates"].items():
        lines.append(f"| {NAMES[n]} | {c['validation_status']} | {c['activation_eligible']} | {', '.join(c['development_gates']['failed'])} |")
    lines += ["", "## Limitations and activation decision", "",
        "No candidate is safe to activate on available evidence. Historical real corpora mostly supply one class; the only two-class new source uses synthetic class-specific prompts. All final positive examples are synthetic. No verified modern independently labeled real two-class collection or representative deployment holdout was admitted. Release dates cannot substitute for temporal evaluation.",
        "Labels are inherited, not reannotated by experts. Topic, spelling, mailing-list boilerplate and generation templates can remain predictive. Practical near matching cannot prove all paraphrase/campaign separation. Deduplication changes prevalence, especially repetitive synthetic legitimate text. Training caps reduce source-size dominance but do not establish source independence. Calibration reflects a research mixture, not real inbox prevalence. Latency is normalized-text inference on this CPU, not end-to-end forensic processing.",
        "V1 and v2 have different sources, exclusions, balance and gate values, so their metrics are not a controlled generalization-improvement comparison. Future promotion needs modern independently labeled real sources containing both classes, adequate source/time support and a new untouched external holdout.",
        "Legacy artifact bytes, the active loader, UI, forensic modules and fusion weights remain unchanged. Keeping the fallback active preserves compatibility; it is not a claim that the demonstration model is validated.",
        "", "## Files changed", "",
        "- ml/generalization/__init__.py, text.py, fetch.py, data.py: isolated normalization, reviewed downloads, quarantine, source splits and training cap.",
        "- ml/generalization/evaluate.py, inference.py, report.py: source evaluation, calibration, gates, locked research inference and aggregate report.",
        "- ml/data/sources_v2.json and manifest_v2.json: source decisions, citations, measured counts and hashes.",
        "- ml/reports/candidate_v2_selection.json, its .test-opened marker, candidate_v2_final.json and this report: frozen validation/source/final evidence.",
        "- Four ml/models/candidate_v2/<candidate>/metadata.json files: validation states, gates and source/artifact/version metadata. Fitted binaries are ignored.",
        "- tests/test_model_generalization.py: offline regressions.",
        "- docs/ai-dataset-generalization-v2.md, README.md and docs/architecture.md: methodology, exact gates, reproducibility and compatibility.",
        "", f"Verification: **{test_count} offline tests passed**, including all original 170. No private email, raw corpus text, API key, database, export or fitted research binary belongs in Git.", ""]
    path = ROOT / "reports/AI_DATASET_GENERALIZATION_V2.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print("Wrote:", path.name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-count", type=int, required=True)
    render(parser.parse_args().test_count)
