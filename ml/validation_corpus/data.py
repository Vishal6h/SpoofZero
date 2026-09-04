"""Provenance, duplicate-family quarantine, chronology and sealed corpus roles."""
import argparse
from collections import Counter
import csv
from datetime import datetime, date
import json
from pathlib import Path
from ml.data_pipeline import ROOT, SEED, Components, digest, near_pairs, write_json
from ml.experiment import checked_rows
from ml.generalization.data import buckets, assert_disjoint, balance_training
from ml.generalization.data import normalize_example as v2_normalize
from ml.text import message_parts
from .text import VERSION, feature_text, PATTERNS

TAGS = {"REAL", "SYNTHETIC", "UNKNOWN"}
EXTERNAL_SOURCES = frozenset({"smishx"})
DATASET = ROOT / "data/processed/real_world_v1"
RECIPE = ROOT / "data/sources_real_world_v1.json"
ROLES = ("train", "validation", "validation_historical", "test", "external",
         "synthetic_stress", "date_unknown")

def parse_date(value):
    """SpaPhish schema specifies DD/MM/YYYY; never infer dates from release/ID."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.strptime(value.strip(), "%d/%m/%Y").date().isoformat()
    except ValueError:
        return None

def temporal_role(start, end):
    if not start or not end:
        return "date_unknown"
    first, last = date.fromisoformat(start), date.fromisoformat(end)
    if first > last:
        raise ValueError("Reversed date interval")
    if last < date(2023, 1, 1):
        return "train"
    if first >= date(2023, 1, 1) and last < date(2024, 1, 1):
        return "validation"
    if first >= date(2024, 1, 1) and last <= date(2025, 12, 31):
        return "test"
    return "date_unknown"  # Straddling intervals cannot be assigned an invented date.

def normalize_example(example):
    tag = example.get("reality", "UNKNOWN")
    if tag not in TAGS:
        raise ValueError("Reality must be REAL, SYNTHETIC, or UNKNOWN")
    record = v2_normalize(example)
    if record is None:
        return None
    text = feature_text(example)
    if not text or not any(c.isalpha() for c in text):
        return None
    body_text = feature_text({"body": record["body"]})
    record.update(text=text, template_hash=digest(text),
        body_hash=digest(body_text) if len(body_text.split()) >= 10 else None,
        reality=tag, synthetic=tag == "SYNTHETIC",
        channel=example.get("channel", "email"), role=example["role"],
        date_start=example.get("date_start"), date_end=example.get("date_end"),
        date_quality=example.get("date_quality", "UNKNOWN"),
        sources=sorted(set(example.get("sources", record["sources"]))),
        prior_family=example.get("group_id"), previously_seen=bool(example.get("previously_seen", False)))
    return record

def deduplicate(records):
    """Reuse graph primitives; retain all provenance until cross-role quarantine."""
    records = sorted(records, key=lambda r: r["id"])
    if len({r["id"] for r in records}) != len(records):
        raise ValueError("Source IDs must be unique")
    components, seen = Components(len(records)), {}
    stats = {"input": len(records)}
    for stage, keys in (("exact", ("exact_hash",)), ("template_body_family", ("template_hash", "body_hash", "prior_family"))):
        merges = 0
        for i, r in enumerate(records):
            for key in keys:
                value = r.get(key)
                if not value:
                    continue
                token = (key, value)
                if token in seen:
                    if components.find(i) != components.find(seen[token]):
                        merges += 1
                    components.union(i, seen[token])
                else:
                    seen[token] = i
        stats[stage + "_merges"] = merges
    representatives = [min(g, key=lambda r: r["id"]) for g in buckets(records, components)]
    positions = {r["id"]: i for i, r in enumerate(records)}
    edges = 0
    for left, right in near_pairs(representatives):
        components.union(positions[representatives[left]["id"]], positions[representatives[right]["id"]])
        edges += 1
    kept, quarantine = [], []
    reasons, duplicate_rows = Counter(), 0
    for group in buckets(records, components):
        roles = {r["role"] for r in group}
        sources = sorted({s for r in group for s in r["sources"]})
        reason = None
        if len({r["label"] for r in group}) > 1:
            reason = "conflicting_labels"
        elif any(r["protected"] for r in group):
            reason = "previously_exposed_test_family"
        elif len(roles) > 1:
            reason = "cross_partition_family"
        elif set(sources) & EXTERNAL_SOURCES and not set(sources) <= EXTERNAL_SOURCES:
            reason = "cross_external_source_family"
        group_id = digest("|".join(sorted(r["id"] for r in group)))
        if reason:
            reasons[reason] += len(group)
            quarantine.append({"group_id": group_id, "rows": len(group), "reason": reason})
            continue
        r = dict(min(group, key=lambda r: r["id"]))
        realities = {r["reality"] for r in group}
        r.update(sources=sources, group_id=group_id, member_count=len(group),
                 reality=next(iter(realities)) if len(realities) == 1 else "UNKNOWN")
        r["synthetic"] = r["reality"] == "SYNTHETIC"
        if all(x["date_start"] and x["date_end"] for x in group):
            r["date_start"] = min(x["date_start"] for x in group)
            r["date_end"] = max(x["date_end"] for x in group)
        else:
            r["date_start"] = r["date_end"] = None
            r["date_quality"] = "UNKNOWN"
        if len({x["date_quality"] for x in group}) > 1:
            r["date_quality"] = "MIXED_INTERVAL"
        kept.append(r)
        duplicate_rows += len(group) - 1
    stats.update(near_edges=edges, duplicates_removed=duplicate_rows,
                 quarantine_rows=dict(reasons), retained=len(kept))
    assert len(records) == len(kept) + duplicate_rows + sum(reasons.values())
    return kept, stats, quarantine

def assert_external_isolation(train, validation, external, external_sources=EXTERNAL_SOURCES):
    fitting_sources = {s for r in train + validation for s in r["sources"]}
    external_sources = set(external_sources)
    if fitting_sources & external_sources:
        raise ValueError("External source entered development")
    if any(not set(r["sources"]) <= external_sources for r in external):
        raise ValueError("Unreviewed external provenance")
    assert_disjoint({"development": train + validation, "external": external})

def assert_temporal_integrity(train, validation, test):
    for role, rows in (("train", train), ("validation", validation), ("test", test)):
        for r in rows:
            if r["date_quality"] not in {"DOCUMENTED_MESSAGE_DATE", "DOCUMENTED_COLLECTION_BOUND"}:
                raise ValueError("Unknown temporal evidence")
            if temporal_role(r["date_start"], r["date_end"]) != role:
                raise ValueError("Future or overlapping interval in temporal split")
    assert_disjoint({"train": train, "validation": validation, "test": test})

def overlap_quality(rows):
    labels = {r["label"] for r in rows}
    if labels != {0, 1}:
        return "SINGLE_CLASS"
    if all(r["reality"] == "SYNTHETIC" for r in rows):
        return "BOTH_CLASSES_SYNTHETIC"
    if all(r["reality"] == "REAL" for r in rows):
        return "BOTH_CLASSES_REAL"
    return "BOTH_CLASSES_MIXED_OR_UNKNOWN"

def summary(rows):
    source_ids = sorted({r["source"] for r in rows})
    return {"count": len(rows), "class_counts": {str(n): sum(r["label"] == n for r in rows) for n in (0, 1)},
        "reality_counts": {tag: sum(r["reality"] == tag for r in rows) for tag in sorted(TAGS)},
        "reality_class_counts": {tag: {str(n): sum(r["reality"] == tag and r["label"] == n for r in rows) for n in (0, 1)} for tag in sorted(TAGS)},
        "sources": {s: {"count": sum(r["source"] == s for r in rows),
                       "class_counts": {str(n): sum(r["source"] == s and r["label"] == n for r in rows) for n in (0, 1)},
                       "class_overlap_quality": overlap_quality([r for r in rows if r["source"] == s])} for s in source_ids}}

def artifact_audit(rows):
    counts = {}
    for name, pattern in PATTERNS.items():
        counts[name] = {"raw_rows": sum(bool(pattern.search(r["subject"] + "\n" + r["body"])) for r in rows),
                        "normalized_rows": sum(bool(pattern.search(r["text"])) for r in rows)}
    lines = Counter()
    for r in rows:
        for line in {line.strip().casefold() for line in r["body"].splitlines() if len(line.strip()) >= 30}:
            lines[digest(line)] += 1
    return {"static_patterns": counts,
            "repeated_line_hashes": [{"sha256": h, "rows": n} for h, n in sorted(lines.items()) if n >= 20],
            "scope": "All corpus text is scrubbed mechanically; repeated-line/source diagnostics inspect development training only. Raw lines never enter reports."}

def build(destination=DATASET, raw=ROOT / "data/raw/real_world_v1"):
    destination, raw = Path(destination), Path(raw)
    if destination.exists():
        raise FileExistsError("Corpus version is immutable")
    recipe = json.loads(RECIPE.read_text())
    for asset in recipe["assets"]:
        p = raw / asset["filename"]
        if digest(p.read_bytes()) != asset["sha256"]:
            raise ValueError("Unpinned raw asset")
    v2dir = ROOT / "data/processed/public_email_v2"
    old_manifest_path = ROOT / "data/manifest_v2.json"
    old_manifest = json.loads(old_manifest_path.read_text())
    records, input_counts, excluded = [], Counter(), Counter()
    def add(example):
        input_counts[example["source"]] += 1
        r = normalize_example(example)
        if r is None:
            excluded["empty_text"] += 1
        else:
            records.append(r)
    for part in ("train", "validation", "test"):
        for row in checked_rows(v2dir, part, old_manifest):
            synthetic = row["synthetic"]
            role = "synthetic_stress" if synthetic else ("validation_historical" if part == "validation" else part)
            add(dict(row, reality="SYNTHETIC" if synthetic else "REAL", role=role,
                protected=(part == "test" and not synthetic),
                date_start=None if synthetic else "1995-01-01",
                date_end=None if synthetic else "2022-12-31",
                date_quality="UNKNOWN" if synthetic else "DOCUMENTED_COLLECTION_BOUND",
                previously_seen=True))
    with (raw / "spaphish.csv").open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)  # pinned release is comma-separated, despite landing-page prose
        for row in reader:
            if row["Label"] not in {"0", "1"}:
                raise ValueError("Unreviewed SpaPhish label")
            day = parse_date(row["date"])
            add({"source": "spaphish", "source_id": row["hash"], "subject": row["subject"],
                 "body": row["body"], "label": int(row["Label"]), "reality": "REAL",
                 "date_start": day, "date_end": day,
                 "date_quality": "DOCUMENTED_MESSAGE_DATE" if day else "UNKNOWN",
                 "role": temporal_role(day, day)})
    with (raw / "smishx.csv").open(encoding="utf-8-sig", newline="") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if row["label"] == "spam":
                excluded["smishx_generic_spam"] += 1
                continue
            if row["label"] not in {"smishing", "legitimate"}:
                raise ValueError("Unreviewed SMS label")
            add({"source": "smishx", "source_id": str(i), "body": row["SMS"],
                 "label": int(row["label"] == "smishing"), "reality": "REAL",
                 "channel": "sms", "role": "external"})
    print("Global duplicate graph:", len(records), "records", flush=True)
    kept, stats, quarantine = deduplicate(records)
    splits = {role: sorted([r for r in kept if r["role"] == role], key=lambda r: r["id"]) for role in ROLES}
    assert_disjoint(splits)
    assert_external_isolation(splits["train"], splits["validation"] + splits["validation_historical"], splits["external"])
    assert_temporal_integrity(splits["train"], splits["validation"], splits["test"])
    if any(r["reality"] != "REAL" for r in splits["train"]):
        raise ValueError("This preregistered run fits real records only")
    destination.mkdir(parents=True)
    split_info = {}
    for name, rows in splits.items():
        content = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows)
        path = destination / (name + ".jsonl")
        path.write_text(content, encoding="utf-8", newline="\n")
        split_info[name] = dict(summary(rows), sha256=digest(path.read_bytes()))
    manifest = {"dataset_id": "real_world_v1", "recipe": recipe,
        "normalization_version": VERSION, "previous_manifest_sha256": digest(old_manifest_path.read_bytes()),
        "input_representatives": dict(input_counts), "exclusions": dict(excluded),
        "deduplication": stats, "quarantine": quarantine, "splits": split_info,
        "retained": summary(kept), "training_after_cap": summary(balance_training(splits["train"])),
        "artifact_audit": artifact_audit(splits["train"]),
        "temporal": {"available": True, "train_end_bound": "2022-12-31", "validation": "2023",
                     "test": "2024-2025", "quality": "Documented collection bounds plus publisher message dates; dates are not independently verified delivery timestamps."},
        "limitations": ["Previous v2 representatives are reused, not reclassified as fresh evidence.",
            "Near matching operates on coarse representatives using inherited trigram/Jaccard thresholds, not all paraphrases.",
            "Cross-date and cross-role families are quarantined in full; this reduces realistic campaign repetition.",
            "SmishX is a relabeled multi-collection SMS holdout, not a second independent email collection.",
            "Synthetic stress rows were previously exposed in v2; their scores are diagnostics only.",
            "SpaPhish is one collection spanning several contributors; contributor identities cannot establish independent sources."]}
    write_json(destination / "manifest.json", manifest)
    write_json(ROOT / "data/manifest_real_world_v1.json", manifest)
    print("Sealed corpus:", json.dumps({p: s["count"] for p, s in split_info.items()}), flush=True)
    return manifest

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--destination", type=Path, default=DATASET)
    p.add_argument("--raw", type=Path, default=ROOT / "data/raw/real_world_v1")
    args = p.parse_args()
    build(args.destination, args.raw)
