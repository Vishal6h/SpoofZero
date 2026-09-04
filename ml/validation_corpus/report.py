"""Render aggregate frozen evidence; never read or predict email text."""
import argparse
import json
from pathlib import Path
from ml.data_pipeline import ROOT, digest
from ml.report import NAMES
from .evaluate import LOCK, FINAL

OUTPUT = ROOT / "reports/REAL_WORLD_VALIDATION_CORPUS.md"

def cell(value):
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.5f}"
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    return str(value).replace("|", "/").replace("\n", " ")

def table(headers, rows):
    return "\n".join(["| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |"] +
        ["| " + " | ".join(cell(x) for x in row) + " |" for row in rows]) + "\n"

def render(test_count, output=OUTPUT, lock_path=LOCK, final_path=FINAL):
    lock_path, final_path, output = map(Path, (lock_path, final_path, output))
    lock, final = json.loads(lock_path.read_text()), json.loads(final_path.read_text())
    manifest_path = ROOT / "data/manifest_real_world_v1.json"
    manifest = json.loads(manifest_path.read_text())
    if final["selection_sha256"] != digest(lock_path.read_bytes()) or final["dataset_manifest_sha256"] != digest(manifest_path.read_bytes()):
        raise ValueError("Frozen report inputs do not match")
    selected = lock["selected_model"]
    candidate = final["candidates"][selected]
    recipe = manifest["recipe"]
    counts = manifest["deduplication"]
    lines = [
        "# Real-World Validation Corpus: frozen evidence\n",
        "**Legacy model remains active and byte-for-byte unchanged. No candidate was activated.**\n",
        f"Protected checkpoint: {recipe['protected_commit']}. Research choice: **{NAMES[selected]}**. "
        f"Status: **{candidate['status']}**. Activation recommended: **No**. Full offline suite: **{test_count} tests passed**.\n",
        "This milestone adds a dated real-email corpus and a fresh external SMS corpus. It does not establish real-inbox accuracy. "
        "All four candidates are reported after selection, and their final results cannot change the locked model or thresholds.\n",
        "## Inspection findings and reuse\n",
        "V1's source-transfer failure and v2's 66.96% worst-source error outweighed excellent mixed-corpus scores. "
        "All v2 final-test positives were synthetic. The existing normalizers, duplicate graph primitives, model factory, "
        "calibration, metrics, source-aware evaluation and numerical deployment gates were reused without editing their frozen source. "
        "Production inference still uses the original model; its 35% fusion contribution, the forensic pipeline and UI are unchanged.\n",
        "## Every dataset considered: admitted and reused\n",
        "Counts below distinguish original raw releases from retained representatives. This run reads 31,057 prior v2 "
        "representatives and 2,276 eligible new records; it does not pretend to rediscover the historical raw corpora. "
        "Source URLs carry publisher attribution. Original CC-BY/CC-BY-SA usage notes remain in the catalog.\n"]
    rows=[]
    for source in recipe["sources"]:
        name=source["name"]
        s=manifest["retained"]["sources"][name]
        rows.append([f"[{name}]({source['source']})",source["publisher"],source["license"],source["nature"],
                     source["raw_count"],manifest["input_representatives"].get(name,0),s["count"],
                     s["class_counts"].get("0",0),s["class_counts"].get("1",0),source["decision"]])
    lines.append(table(["Source","Publisher","License","Origin","Raw release","Input eligible","Retained","Legit","Malicious","Role"],rows))
    lines += ["SpaPhish's source release has 1,395 rows (664 legitimate / 731 phishing); SmishX has 1,200 "
              "(622 legitimate / 259 smishing / 319 generic spam). Only legitimate and smishing SMS enter the corpus. "
              "Only CSV text and JSON schema were downloaded; no raw MIME, attachments, archives, leaked inboxes or scripts.\n",
              "## Other reviewed datasets and exclusions\n"]
    rows=[]
    for s in recipe["considered"]:
        rows.append([f"[{s['name']}]({s['source']})",s["publisher"],s["license"],s.get("period"),
                     s["nature"],s["classes"],s.get("reported_count"),s["admitted_count"],s["reason"]])
    lines.append(table(["Dataset","Publisher","License/usage","Period","Origin","Classes","Reported raw count","Admitted","Reason"],rows))
    lines += ["Inherited v2 decisions are explicitly marked in the JSON catalog. Search-engine suggestions without substantive "
              "provenance review are not counted as dataset decisions. The Codebook paper explicitly uses Nazario: "
              "its annotation release is not a new independent collection. Phishing Pot's raw MIME payload risk "
              "prevented admission under this milestone's text-only restriction. Sting9's conflicting license statements "
              "were not resolved by assuming the more permissive one.\n",
              "## Class overlap, dates and corpus quality\n"]
    rows=[]
    for s in recipe["sources"]:
        rows.append([s["name"],s["class_overlap_quality"],s["period"],s["usage_notes"]])
    lines.append(table(["Source","Class overlap quality","Date evidence","Provenance/usage limitations"],rows))
    lines += ["One modern real **email** collection supplies both labels: SpaPhish. Its contributors are not counted as "
              "independent environments. SmishX contains both real classes but combines different underlying SMS origins "
              "without row-level source mapping. Synthetic same-source class overlap is tracked separately.\n",
              "## Construction, duplicates and artifacts\n",
              f"Input: **{counts['input']}** eligible representatives. Removed **{counts['duplicates_removed']}** duplicate rows. "
              f"Quarantined rows by reason: **{json.dumps(counts['quarantine_rows'])}**. "
              f"Retained **{counts['retained']}** representatives. "
              f"Exact component merges: {counts['exact_merges']}; additional template/body/prior-family merges: "
              f"{counts['template_body_family_merges']}; near edges: {counts['near_edges']}. "
              "Edges are not additional removed-row counts. No new conflicting-label family was found; "
              "the predecessor v2 corpus had already quarantined 12 conflicting rows and exposed v1 families.\n",
              "Cross-period/source/partition families are quarantined in full. Previously exposed test rows are exclusion "
              "references, never fresh evidence. Near matching uses inherited unfitted hashing and trigram Jaccard, "
              "which cannot guarantee detection of every paraphrase. Prior coarse representatives omit some discarded "
              "variants, and quarantine changes campaign frequency.\n"]
    lines.append(table(["Static artifact pattern","Training raw rows","Remaining normalized matches"],
        [[name,v["raw_rows"],v["normalized_rows"]] for name,v in manifest["artifact_audit"]["static_patterns"].items()]))
    lines.append(f"Repeated training-line groups with >=20 observations: **{len(manifest['artifact_audit']['repeated_line_hashes'])}**. "
                 "Only hashes/counts are preserved. These groups may be signatures, mailing-list notices or repeated templates; "
                 "they were not manually relabeled or used to learn test-dependent removal rules.\n")
    diagnostic=lock["source_predictability"]
    lines += ["## Source-identity diagnostic\n",
        table(["Accuracy","Balanced accuracy","Majority-source baseline","Extremely predictable (>90%)"],
            [[diagnostic["validation_accuracy"],diagnostic["validation_balanced_accuracy"],
              diagnostic["majority_source_baseline"],diagnostic["validation_accuracy"]>.90]]),
        "This is a separate development-only text-to-source classifier. High accuracy signals surviving language, topic "
        "or collection distinctions; it does not by itself prove malicious label leakage. No external or final corpus "
        "fits this diagnostic, and it never affects production inference.\n",
        "## Partitions, reality tags and temporal integrity\n"]
    rows=[]
    for part,info in manifest["splits"].items():
        rows.append([part,info["count"],info["class_counts"]["0"],info["class_counts"]["1"],
                     info["reality_counts"]["REAL"],info["reality_counts"]["SYNTHETIC"],info["reality_counts"]["UNKNOWN"]])
    fitted=lock["training_after_cap"]
    rows.append(["Actually fitted after cap",fitted["count"],fitted["class_counts"]["0"],fitted["class_counts"]["1"],
                 fitted["reality_counts"]["REAL"],0,0])
    lines.append(table(["Partition","Total","Legit","Malicious","REAL","SYNTHETIC","UNKNOWN"],rows))
    lines += [
        "Training uses real historical v2 training plus SpaPhish through 2022. Thresholds use only SpaPhish 2023; "
        "the mixed validation report also includes historical v2 development validation. That historical portion is "
        "previously exposed development evidence, not a chronological or fresh holdout. The newest SpaPhish "
        "2024–2025 slice is the final temporal test. Missing dates stay out of training and temporal evaluation.\n",
        "Historical dates use a conservative publisher collection bound through 2022; SpaPhish dates follow its documented "
        "DD/MM/YYYY schema. Chronology is conditional on these source reports, not independently authenticated delivery "
        "timestamps. The pinned CSV is comma-delimited despite the landing page's semicolon description.\n",
        "SmishX is entirely external and was read for evaluation only after selection, artifact/code/data/policy hashes "
        "and thresholds were locked. Preparation used its text solely for fixed normalization/deduplication and aggregate "
        "admission checks. It never fit TF-IDF, a classifier, calibration, thresholds, model selection or the source diagnostic. "
        "This is independent **SMS** transfer, not external email validation.\n",
        "## Models, selection and threshold trade-offs\n",
        "The four inherited fixed TF-IDF models use word uni/bigrams, min_df=2, max_df=0.98, at most 50,000 features, "
        "sublinear TF and Unicode accent stripping. LR/SVM use C=1 and balanced class weights; NB uses alpha=1. "
        "Sigmoid calibration learns out-of-fold predictions with TF-IDF fitted within each training fold. "
        "Seed: 20260904. No hyperparameter sweep or synthetic fitting.\n"]
    lines.append(table(["Candidate","Mixed-val precision","Recall","F1","Brier","Worst LOSO error","Selection score","p95 ms","Review / high"],
        [[NAMES[n], c["validation"]["pooled"]["precision"],c["validation"]["pooled"]["recall"],
          c["validation"]["pooled"]["f1"],c["validation"]["pooled"]["brier_score"],
          c["source_evaluation"]["summary"]["worst_source_error"],c["selection_score"],c["inference_ms_p95"],
          [c["thresholds"]["suspicious"],c["thresholds"]["high"]]] for n,c in lock["candidates"].items()]))
    lines.append(f"The locked research choice is **{NAMES[selected]}**, using the unchanged source-aware ranking "
        "(50% specificity of the worst source, 25% macro recall, 15% mixed F1, 10% calibration; gate passes first). "
        "Selection is a research comparison, not promotion. Ties prefer simplicity/latency. The final holdout never selects a winner.\n")
    lines.append(table(["Candidate","2023 validation FP","FN","Review target met","High target met","Review threshold","High threshold"],
        [[NAMES[n],c["temporal_validation"]["overall"]["pooled"]["false_positives"],
          c["temporal_validation"]["overall"]["pooled"]["false_negatives"],c["thresholds"]["review_target_met"],
          c["thresholds"]["high_target_met"],c["thresholds"]["suspicious"],c["thresholds"]["high"]]
          for n,c in lock["candidates"].items()]))
    lines.append("Bands are low below review, suspicious from review to below high, and high at or above high. "
        "When the recall/FPR target is infeasible the inherited selector records failure and chooses a validation F2 fallback; "
        "that is not a usable deployment threshold. High-band infeasibility similarly remains explicit. Full validation "
        "threshold grids and high-band final confusion matrices are preserved in JSON; no threshold was adjusted after test.\n")
    for part,title in (("test","Final temporal real-email test, 2024–2025"),
                       ("external","Fresh external SmishX transfer"),
                       ("synthetic_stress","Previously exposed synthetic stress test"),
                       ("date_unknown","Unknown-date real-email diagnostic")):
        lines.append("## "+title+"\n")
        entries=[(n,c["evaluations"][part]["overall"]["pooled"]) for n,c in final["candidates"].items() if c["evaluations"][part]["overall"]]
        lines.append(table(["Candidate","N","Accuracy","Precision","Recall","F1","FP","FN","CM [[TN,FP],[FN,TP]]"],
            [[NAMES[n],m["count"],m["accuracy"],m["precision"],m["recall"],m["f1"],m["false_positives"],m["false_negatives"],m["confusion_matrix"]] for n,m in entries]))
        lines.append(table(["Candidate","ROC-AUC","PR-AUC (AP)","Brier","Log loss","ECE"],
            [[NAMES[n],m["roc_auc"],m["pr_auc_average_precision"],m["brier_score"],m["log_loss"],m["ece_10_equal_width"]] for n,m in entries]))
    lines += ["Calibration metrics and ten-bin reliability tables are preserved for every candidate and cohort. "
              "Brier is influenced by discrimination/prevalence as well as calibration; small samples and class imbalance "
              "limit ECE interpretation. These scores do not establish calibrated operational probabilities.\n",
              "## Selected-model real/synthetic class separation\n"]
    rows=[]
    for part in ("test","external","synthetic_stress","date_unknown"):
        for cohort,m in candidate["evaluations"][part]["by_reality_class"].items():
            rows.append([part,cohort,m["count"] if m else 0,m["false_positive_rate"] if m else None,
                         m["false_negative_rate"] if m else None,m["brier_score"] if m else None])
    lines.append(table(["Partition","Cohort","N","FPR","FNR","Brier"],rows))
    lines += ["REAL/SYNTHETIC/UNKNOWN per-class and per-source metrics for **all four** models are included in the frozen final JSON. "
              "Unsupported single-class precision/F1/AUC are null. Unknown-date messages are still REAL; temporal quality "
              "and provenance tags are distinct. Synthetic rows contribute zero deployment evidence.\n",
              "## Per-source generalization and source macro results\n"]
    rows=[]
    for n,c in lock["candidates"].items():
        for fold in c["source_evaluation"]["leave_one_source_out"]:
            if fold["status"]!="EVALUATED":
                rows.append([NAMES[n],fold["held_out_sources"],fold["status"],None,None,None,None,None]);continue
            for s,m in fold["evaluation"]["per_source"].items():
                rows.append([NAMES[n],s,m["count"],m["recall"],m["false_positive_rate"],
                             m["worst_class_error"],m["brier_score"],m["ece_10_equal_width"]])
    lines.append(table(["Candidate","Held-out source","N","Recall","FPR","Worst class error","Brier","ECE"],rows))
    rows=[]
    for n,c in lock["candidates"].items():
        s=c["source_evaluation"]["summary"];macro=s["macro"]
        rows.append([NAMES[n],macro["recall"]["value"],macro["false_positive_rate"]["value"],
                     macro["brier_score"]["value"],macro["ece_10_equal_width"]["value"],
                     s["worst_source_error"],s["minimum_support"]])
    lines.append(table(["Candidate","Macro recall","Macro FPR","Macro Brier","Macro ECE","Worst error","Min source N"],rows))
    lines.append("Each macro averages only supported source metrics, with denominators recorded in JSON. "
        "LOSO/transfer use training partitions only. Model and thresholds are fitted without the checking source. "
        "The SpaPhish training-era phishing class is sparse, which limits source-specific conclusions.\n")
    rows=[]
    for n,c in lock["candidates"].items():
        for fold in c["source_evaluation"]["paired_source_transfer"]:
            if fold["status"]=="EVALUATED":
                m=fold["evaluation"]["pooled"]
                rows.append([NAMES[n],fold["held_out_sources"],m["recall"],m["false_positive_rate"],m["f1"],m["false_positives"],m["false_negatives"]])
    lines.append(table(["Candidate","Unseen source pair","Recall","FPR","F1","FP","FN"],rows))
    lines.append("## Temporal year cohorts: selected model\n")
    lines.append(table(["Year","N","Precision","Recall","FPR","F1","FP","FN"],
        [[year,m["count"],m["precision"],m["recall"],m["false_positive_rate"],m["f1"],m["false_positives"],m["false_negatives"]]
         for year,m in candidate["evaluations"]["test"]["by_year"].items()]))
    lines.append("## Every deployment gate: selected model\n")
    rows=[]
    for stage in ("inherited_gates","additional_gates"):
        for name,g in candidate[stage]["gates"].items():
            rows.append([stage,name,g["actual"],g["operator"],g["limit"],"PASS" if g["passed"] else "FAIL"])
    lines.append(table(["Stage","Gate","Observed","Operator","Limit","Result"],rows))
    lines.append("All inherited v2 numeric values remain unchanged. Temporal and external failures are additional blockers; "
        "excellent pooled performance cannot override them. The external real-email support gate is intentionally not "
        "satisfied by SMS, and only one qualifying modern real-email collection exists. Missing evidence fails closed.\n")
    lines.append(table(["Candidate","Status","Inherited gates failed","Additional gates failed","Active"],
        [[NAMES[n],c["status"],len(c["inherited_gates"]["failed"]),len(c["additional_gates"]["failed"]),c["active"]]
         for n,c in final["candidates"].items()]))
    lines.append("Deployment evidence counts: "+cell(final["deployment_evidence"])+". "
        "No model is recommended for activation. Retaining the legacy fallback does not validate its accuracy; "
        "the ML output remains one evidence source among authentication, identity, reputation, relay and attachments.\n")
    lines += ["## Files changed and tests\n",
        "- README.md; docs/architecture.md; docs/real-world-validation-corpus.md.\n"
        "- ml/validation_corpus/{__init__,text,data,fetch,evaluate,report}.py.\n"
        "- ml/data/sources_real_world_v1.json; ml/data/manifest_real_world_v1.json.\n"
        "- ml/models/candidate_real_world_v1/{logistic,logistic_sigmoid,linear_svm_sigmoid,multinomial_nb}/metadata.json.\n"
        "- ml/reports/candidate_real_world_v1_selection.json, its .test-opened marker, candidate_real_world_v1_final.json, and this report.\n"
        "- tests/test_real_world_corpus.py.\n",
        f"**{test_count} offline tests pass** (217 existing plus {test_count-217} new). "
        "Tests use invented fixtures, temporary local files and mocked download calls; they require no raw corpus, "
        "candidate binary, private email, API key or network. They cover reality tags, overlap, dates/future leakage, "
        "duplicates/conflicts, external isolation, artifacts, source diagnostics, all gates, immutable locks, "
        "single-use finalization, inactive metadata and protected legacy hashes.\n",
        "Raw/processed text, temporary runs and candidate binaries stay ignored. No dependencies were added. "
        "No model activation, Git commit, remote or push is part of this milestone.\n",
        "## Remaining limitations and interpretation\n",
        "SpaPhish is Spanish while most historical fitting data is English; temporal behavior mixes age, language, "
        "topic, class-prior and source shifts. Its early phishing support is small and later phishing dominates. "
        "The external SMS collection has short text, live-URL selection bias in its original study, and mixed underlying "
        "origins. Neither supplies an independent modern English business-email test. BEC coverage is not separately "
        "adjudicated. Real provenance is publisher-reported; anonymization and identifier masking alter linguistic clues. "
        "Temporal bounds are not cryptographically verified. Exact/template/near screening is practical, not exhaustive. "
        "Repeated campaign removal and cap-based fitting alter prevalence. The revealed final corpora are now spent for "
        "future tuning; any future improved model needs another untouched external email collection.\n",
        "See [methodology and reproduction](../../docs/real-world-validation-corpus.md), "
        "[source catalog](../data/sources_real_world_v1.json), "
        "[locked development results](candidate_real_world_v1_selection.json) and "
        "[complete final metrics](candidate_real_world_v1_final.json).\n"]
    output.write_text("\n".join(lines),encoding="utf-8",newline="\n")
    print("Wrote",output,flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--test-count",type=int,required=True)
    p.add_argument("--output",type=Path,default=OUTPUT)
    args=p.parse_args()
    render(args.test_count,args.output)
