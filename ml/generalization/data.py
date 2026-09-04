"""Build v2 without reusing exposed v1 evaluation examples as fresh evidence."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

from ml.data_pipeline import (ROOT, SEED, Components, digest, near_pairs, read_rows,
                              write_json)
from ml.experiment import checked_rows
from ml.text import message_parts, normalized_content
from .text import VERSION, feature_text, METADATA_LINE, FILENAME, COLLECTOR

OLD_SOURCES = frozenset({"ling", "spamassassin", "nazario", "nigerian_fraud"})


def normalize_example(example):
    if type(example.get("label")) is not int or example["label"] not in (0, 1):
        raise ValueError("A reviewed integer 0/1 label is required")
    if not isinstance(example.get("source"), str) or not example["source"]:
        raise ValueError("Documented source provenance is required")
    subject, body = message_parts(example)
    text = feature_text({"subject": subject, "body": body})
    if not text or not any(c.isalpha() for c in text):
        return None
    exact = digest(normalized_content(subject, body))
    source, source_id = example["source"], str(example.get("source_id", ""))
    body_text = feature_text({"body": body})
    return {"subject": subject, "body": body, "label": example["label"],
            "source": source, "source_id": source_id,
            "id": digest(source + ":" + source_id + ":" + exact),
            "exact_hash": exact, "template_hash": digest(text),
            "body_hash": digest(body_text) if len(body_text.split()) >= 10 else None,
            "text": text, "sources": [source],
            "previously_seen": source in OLD_SOURCES,
            "protected": bool(example.get("protected", False)),
            "synthetic": bool(example.get("synthetic", False))}


def buckets(records, components):
    grouped = defaultdict(list)
    for index, record in enumerate(records):
        grouped[components.find(index)].append(record)
    return list(grouped.values())


def deduplicate(records):
    """Keep conflict/protection provenance until the whole duplicate graph closes."""
    records = sorted(records, key=lambda r: r["id"])
    if len({r["id"] for r in records}) != len(records):
        raise ValueError("Input source IDs must identify distinct rows")
    components = Components(len(records))
    stats = {"input": len(records)}
    for stage in ("exact", "template"):
        seen, edges = {}, 0
        for i, record in enumerate(records):
            keys = [record[stage + "_hash"]]
            if stage == "template" and record["body_hash"]:
                keys.append("body:" + record["body_hash"])
            for key in keys:
                if key in seen:
                    if components.find(i) != components.find(seen[key]):
                        edges += 1
                    components.union(i, seen[key])
                else:
                    seen[key] = i
        stats[stage + "_component_merges"] = edges
    # Reuse v1's unfitted hashing/Jaccard near detector after coarse collapse.
    groups = buckets(records, components)
    representatives = [min(group, key=lambda r: r["id"]) for group in groups]
    positions = {r["id"]: i for i, r in enumerate(records)}
    near_edges = 0
    for left, right in near_pairs(representatives):
        components.union(positions[representatives[left]["id"]], positions[representatives[right]["id"]])
        near_edges += 1
    stats["near_edges"] = near_edges
    kept, quarantine = [], []
    duplicate_rows = conflicting_rows = protected_rows = protected_groups = 0
    for group in buckets(records, components):
        reason = None
        if len({r["label"] for r in group}) > 1:
            conflicting_rows += len(group)
            reason = "conflicting_labels"
        elif any(r["protected"] for r in group):
            protected_rows += len(group)
            protected_groups += 1
            reason = "exposed_v1_validation_or_test_family"
        if reason:
            quarantine.append({"group_hash": digest("|".join(r["id"] for r in group)),
                               "row_count": len(group), "reason": reason})
            continue
        record = dict(min(group, key=lambda r: r["id"]))
        record["sources"] = sorted({s for r in group for s in r["sources"]})
        record["group_id"] = digest("|".join(r["id"] for r in group))
        record["previously_seen"] = any(r["previously_seen"] for r in group)
        record["synthetic"] = any(r["synthetic"] for r in group)
        record["member_count"] = len(group)
        kept.append(record)
        duplicate_rows += len(group) - 1
    stats.update(duplicates_removed=duplicate_rows, conflicting_rows_quarantined=conflicting_rows,
                 exposed_v1_rows_quarantined=protected_rows,
                 exposed_v1_groups_quarantined=protected_groups, retained=len(kept))
    assert len(records) == len(kept) + duplicate_rows + conflicting_rows + protected_rows
    return sorted(kept, key=lambda r: r["id"]), stats, quarantine


def assert_disjoint(splits):
    for key in ("id", "exact_hash", "template_hash", "body_hash", "group_id"):
        names = list(splits)
        values = [{r[key] for r in splits[name] if r.get(key)} for name in names]
        if any(values[i] & values[j] for i in range(len(values)) for j in range(i + 1, len(values))):
            raise ValueError("Duplicate family crosses data partitions")


def split_records(records, seed=SEED):
    # Split each sorted source/class/exposure stratum explicitly, with no fallback
    # that could put an exposed or tiny source into a supposedly fresh final test.
    strata = defaultdict(list)
    for r in sorted(records, key=lambda r: r["id"]):
        if r["protected"]:
            raise ValueError("Protected v1 evaluation record was not quarantined")
        strata[(tuple(r["sources"]), r["label"], r["previously_seen"])].append(r)
    result = {"train": [], "validation": [], "test": []}
    small = []
    for (sources, label, seen), rows in sorted(strata.items()):
        if len(rows) < 8:
            result["train"].extend(rows)
            small.append({"sources": list(sources), "label": label, "count": len(rows)})
            continue
        development, test = (rows, []) if seen else train_test_split(
            rows, test_size=.15, random_state=seed, shuffle=True)
        validation_size = math.ceil(len(rows) * .15)
        train, validation = train_test_split(development, test_size=validation_size,
                                            random_state=seed, shuffle=True)
        for name, part in (("train", train), ("validation", validation), ("test", test)):
            result[name].extend(part)
    result = {name: sorted(rows, key=lambda r: r["id"]) for name, rows in result.items()}
    assert_disjoint(result)
    if any(r["previously_seen"] for r in result["test"]):
        raise ValueError("Previously exposed corpus entered fresh final research test")
    return result, small


def balance_training(records, cap=1500, seed=SEED):
    if type(cap) is not int or cap < 1:
        raise ValueError("Training cap must be a positive integer")
    groups = defaultdict(list)
    for r in records:
        groups[(tuple(r["sources"]), r["label"])].append(r)
    selected = []
    for group in groups.values():
        selected.extend(sorted(group, key=lambda r: digest(str(seed) + ":" + r["id"]))[:cap])
    return sorted(selected, key=lambda r: r["id"])


def summaries(records):
    return {"count": len(records),
            "class_counts": dict(sorted(Counter(str(r["label"]) for r in records).items())),
            "source_counts": dict(sorted(Counter(r["source"] for r in records).items())),
            "source_class_counts": {
                s: dict(Counter(str(r["label"]) for r in records if r["source"] == s))
                for s in sorted({r["source"] for r in records})},
            "synthetic_count": sum(r["synthetic"] for r in records)}


def read_source(source, raw, protected_hashes):
    path = Path(raw) / source["file"]
    content = path.read_bytes()
    expected = source.get("sha256")
    if expected:
        valid = digest(content) == expected
    else:
        algorithm, checksum = source["checksum"].split(":", 1)
        valid = hashlib.new(algorithm, content).hexdigest() == checksum
    if not valid:
        raise ValueError("Source checksum differs from the reviewed recipe")
    label_map = source.get("label_map", {str(source.get("retain_original_label")): source.get("label")})
    subject_field, body_field = source.get("subject_field", "subject"), source.get("body_field", "body")
    records, counts = [], Counter()
    csv.field_size_limit(2**24)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        needed = {body_field, "label"} | ({subject_field} if subject_field else set())
        if not needed.issubset(reader.fieldnames or []):
            raise ValueError("CSV does not match its reviewed subject/body/label adapter")
        for index, row in enumerate(reader):
            counts["raw"] += 1
            if None in row:
                counts["malformed_csv_excluded"] += 1
                continue
            if row.get("label") not in label_map:
                counts["excluded_other_labels" if row.get("label") in ("0", "1") else "invalid_label_excluded"] += 1
                continue
            counts["label_eligible"] += 1
            record = normalize_example({"subject": row.get(subject_field) if subject_field else "",
                "body": row.get(body_field), "label": label_map[row["label"]],
                "source": source["name"], "source_id": str(index),
                "synthetic": source.get("synthetic", False)})
            if record is None:
                counts["empty_excluded"] += 1
                continue
            record["protected"] = record["exact_hash"] in protected_hashes
            records.append(record)
            counts["usable_before_deduplication"] += 1
    return records, dict(source, sha256=digest(content), counts=dict(counts))


def artifact_audit(records):
    """Training-only aggregate audit; never export original messages or filenames."""
    counts = Counter()
    source_lines = defaultdict(Counter)
    for r in records:
        raw = r["subject"] + "\n" + r["body"]
        for name, pattern in (("embedded_metadata", METADATA_LINE),
                              ("filenames", FILENAME), ("collector_markers", COLLECTOR)):
            counts[name + "_rows_before"] += bool(pattern.search(raw))
            counts[name + "_rows_after"] += bool(pattern.search(r["text"]))
        # Report hashed repeated lines, not content. Do not fit removal on test.
        lines = {feature_text({"body": line}) for line in r["body"].splitlines()}
        for line in lines:
            if 6 <= len(line.split()) <= 80:
                source_lines[digest(line)][r["source"]] += 1
    repeated = [{"line_sha256": line, "source_counts": dict(c), "count": sum(c.values())}
                for line, c in source_lines.items() if sum(c.values()) >= 20]
    repeated.sort(key=lambda x: (-x["count"], x["line_sha256"]))
    return {"partition": "train_only", "marker_counts": dict(counts),
            "repeated_line_groups": len(repeated), "largest_repeated_lines": repeated[:30],
            "notes": "Counts/hash IDs only. Repeated legitimate prose is not automatically erased. Topic, spelling, template and residual boilerplate can still identify sources."}


def build(recipe_path=ROOT / "data/sources_v2.json",
          output=ROOT / "data/processed/public_email_v2",
          manifest_path=ROOT / "data/manifest_v2.json"):
    output, manifest_path = Path(output), Path(manifest_path)
    if output.exists() or manifest_path.exists():
        raise FileExistsError("Prepared v2 dataset/manifest is immutable")
    recipe = json.loads(Path(recipe_path).read_text())
    v1 = ROOT / "data/processed/public_email_v1"
    old_manifest = json.loads((v1 / "manifest.json").read_text())
    # Only duplicate exclusion uses exposed old evaluation text, never fitting.
    protected = {r["exact_hash"] for split in ("validation", "test")
                 for r in checked_rows(v1, split, old_manifest)}
    original = json.loads((ROOT / "data/sources.json").read_text())
    records, sources = [], []
    for source, raw in ([(s, ROOT / "data/raw") for s in original["sources"]] +
                        [(s, ROOT / "data/raw/v2") for s in recipe["additional_sources"]]):
        rows, summary = read_source(source, raw, protected)
        records.extend(rows)
        sources.append(summary)
    print("Normalizing/deduplicating public rows:", len(records), flush=True)
    records, duplicates, quarantine = deduplicate(records)
    splits, tiny = split_records(records, recipe["seed"])
    if any(len({r["label"] for r in splits[p]}) != 2 for p in splits):
        raise ValueError("Real run needs both classes in every mixed partition")
    output.mkdir(parents=True)
    manifest = {"recipe": recipe, "normalization_version": VERSION, "sources": sources,
                "deduplication": duplicates, "quarantine_group_counts": dict(Counter(q["reason"] for q in quarantine)),
                "retained": summaries(records), "splits": {}, "small_strata_train_only": tiny,
                "protected_v1_manifest_sha256": digest((v1 / "manifest.json").read_bytes()),
                "protected_v1_evaluation_hash_count": len(protected),
                "dataset_id": digest(json.dumps([(r["id"], r["label"], r["template_hash"]) for r in records])),
                "training_cap_per_source_class": 1500, "training_after_cap": summaries(balance_training(splits["train"])),
                "artifact_audit": artifact_audit(splits["train"]),
                "near_duplicate_limitations": "Reuse v1 cosine>=0.90/Jaccard>=0.85 on exact/template/body representatives; fewer than eight shingles use exact/template only. No guarantee against paraphrases or distinct variants of a collapsed component.",
                "temporal_evaluation": {"available": False, "reason": recipe["protocol"]["temporal"]}}
    for name, rows in splits.items():
        path = output / (name + ".jsonl")
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        manifest["splits"][name] = dict(summaries(rows), sha256=digest(path.read_bytes()))
    # Quarantine evidence is local and hashed, with no exported message text.
    write_json(output / "quarantine.json", quarantine)
    write_json(output / "manifest.json", manifest)
    write_json(manifest_path, manifest)
    print(json.dumps({"deduplication": duplicates, "retained": manifest["retained"],
                      "splits": manifest["splits"], "training_after_cap": manifest["training_after_cap"]}, indent=2), flush=True)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, default=ROOT / "data/sources_v2.json")
    parser.add_argument("--output", type=Path, default=ROOT / "data/processed/public_email_v2")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/manifest_v2.json")
    args = parser.parse_args()
    build(args.recipe, args.output, args.manifest)
