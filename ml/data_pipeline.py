"""Normalize, deduplicate, and split public email text before model fitting."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.model_selection import train_test_split

from .text import VERSION, feature_text, message_parts, normalized_content

ROOT = Path(__file__).resolve().parent
SEED = 20260904


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def read_rows(path):
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def normalize_example(example):
    if type(example.get("label")) is not int or example["label"] not in (0, 1):
        raise ValueError("Labels must explicitly be integer 0 or 1")
    if not isinstance(example.get("source"), str) or not example["source"]:
        raise ValueError("Every example needs documented source provenance")
    subject, body = message_parts(example)
    text = feature_text({"subject": subject, "body": body})
    if not text or not any(c.isalpha() for c in text):
        return None
    source_id = str(example.get("source_id", ""))
    exact = digest(normalized_content(subject, body))
    return {"subject": subject, "body": body, "label": example["label"],
            "source": example["source"], "source_id": source_id,
            "id": digest(example["source"] + ":" + source_id + ":" + exact),
            "exact_hash": exact, "template_hash": digest(text), "text": text,
            "sources": [example["source"]]}


def load_sources(recipe, raw_directory):
    csv.field_size_limit(2**24)
    records, summaries = [], []
    for source in recipe["sources"]:
        path = Path(raw_directory) / source["file"]
        content = path.read_bytes()
        algorithm, expected = source["checksum"].split(":", 1)
        if hashlib.new(algorithm, content).hexdigest() != expected:
            raise ValueError("Raw source checksum differs from the reviewed recipe")
        counts = Counter()
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not {"subject", "body", "label"}.issubset(reader.fieldnames or []):
                raise ValueError("Source schema does not match the explicit adapter")
            for index, row in enumerate(reader):
                counts["raw"] += 1
                if row.get("label") != str(source["retain_original_label"]):
                    counts["excluded_other_labels"] += 1
                    continue
                counts["label_eligible"] += 1
                record = normalize_example({"subject": row.get("subject"), "body": row.get("body"),
                    "label": source["label"], "source": source["name"], "source_id": str(index)})
                if record is None:
                    counts["empty_excluded"] += 1
                else:
                    records.append(record)
                    counts["usable_before_deduplication"] += 1
        summaries.append(dict(source, sha256=digest(content), counts=dict(counts)))
    return records, summaries


class Components:
    def __init__(self, size):
        self.parents = list(range(size))

    def find(self, index):
        while index != self.parents[index]:
            self.parents[index] = self.parents[self.parents[index]]
            index = self.parents[index]
        return index

    def union(self, left, right):
        left, right = self.find(left), self.find(right)
        self.parents[max(left, right)] = min(left, right)


def collapse(records, components):
    buckets = defaultdict(list)
    for index, record in enumerate(records):
        buckets[components.find(index)].append(record)
    survivors, duplicate_count, conflicts = [], 0, 0
    for bucket in buckets.values():
        if len({r["label"] for r in bucket}) != 1:
            conflicts += len(bucket)
            continue
        representative = dict(min(bucket, key=lambda r: r["id"]))
        representative["sources"] = sorted({source for record in bucket for source in record["sources"]})
        representative["group_id"] = digest("|".join(sorted(r["id"] for r in bucket)))
        survivors.append(representative)
        duplicate_count += len(bucket) - 1
    return sorted(survivors, key=lambda r: r["id"]), duplicate_count, conflicts


def shingle_set(text):
    words = text.split()
    return {tuple(words[i:i + 3]) for i in range(len(words) - 2)}


def near_pairs(records):
    if len(records) < 2:
        return
    # No fitted vocabulary or labels: this stage is exclusively deduplication.
    vectorizer = HashingVectorizer(n_features=2**20, alternate_sign=False, binary=True,
                                  norm="l2", ngram_range=(3, 3), dtype=np.float64)
    matrix = vectorizer.transform([r["text"] for r in records])
    shingles = [shingle_set(r["text"]) for r in records]
    for start in range(0, len(records), 128):
        similarities = (matrix[start:start + 128] @ matrix.T).tocoo()
        eligible = np.flatnonzero(similarities.data >= 0.90 - 1e-10)
        for index in eligible:
            left, right = start + int(similarities.row[index]), int(similarities.col[index])
            if left >= right or len(shingles[left]) < 8 or len(shingles[right]) < 8:
                continue
            union = shingles[left] | shingles[right]
            if len(shingles[left] & shingles[right]) / len(union) >= 0.85:
                yield left, right


def deduplicate(records):
    records = sorted(records, key=lambda r: r["id"])
    stats = {"input": len(records)}
    for stage in ("exact", "template", "near"):
        components = Components(len(records))
        if stage == "near":
            edges = 0
            for left, right in near_pairs(records):
                components.union(left, right)
                edges += 1
            stats["near_edges"] = edges
        else:
            seen = {}
            for index, record in enumerate(records):
                keys = [record[stage + "_hash"]]
                if stage == "template" and len(feature_text({"body": record["body"]}).split()) >= 10:
                    keys.append("body:" + digest(feature_text({"body": record["body"]})))
                for key in keys:
                    if key in seen:
                        components.union(index, seen[key])
                    else:
                        seen[key] = index
        records, removed, conflicts = collapse(records, components)
        stats[stage + "_duplicates_removed"] = removed
        stats[stage + "_conflicting_rows_excluded"] = conflicts
    stats["retained"] = len(records)
    return records, stats


def split_records(records, seed=SEED):
    records = sorted(records, key=lambda r: r["id"])
    labels = [r["label"] for r in records]
    strata = [str(r["label"]) + ":" + r["source"] for r in records]
    # Small test fixtures may not have enough examples per source stratum.
    if min(Counter(strata).values(), default=0) < 8:
        strata = labels
    positions = np.arange(len(records))
    development, test = train_test_split(positions, test_size=.15, random_state=seed, stratify=strata)
    train, validation = train_test_split(development, test_size=math.ceil(len(records) * .15), random_state=seed,
                                        stratify=[strata[i] for i in development])
    result = {name: [records[i] for i in sorted(indices)]
              for name, indices in (("train", train), ("validation", validation), ("test", test))}
    for key in ("id", "exact_hash", "template_hash", "group_id"):
        partitions = [{r[key] for r in result[name]} for name in result]
        if any(partitions[i] & partitions[j] for i in range(3) for j in range(i + 1, 3)):
            raise ValueError("Duplicate leakage detected")
    return result


def build(recipe_path=ROOT / "data/sources.json", raw_directory=ROOT / "data/raw",
          output=ROOT / "data/processed/public_email_v1", manifest_path=ROOT / "data/manifest.json"):
    output = Path(output)
    if output.exists():
        raise FileExistsError("Prepared dataset is immutable; use a new output directory/version")
    recipe = json.loads(Path(recipe_path).read_text())
    records, summaries = load_sources(recipe, raw_directory)
    records, duplicates = deduplicate(records)
    splits = split_records(records, recipe["seed"])
    output.mkdir(parents=True)
    manifest = {"recipe": recipe, "normalization_version": VERSION, "sources": summaries,
                "deduplication": duplicates, "splits": {},
                "methodology": "Normalize; collapse exact, masked template/body, and >=0.85 trigram-Jaccard near duplicates; quarantine conflicting labels; seeded 70/15/15 source+label stratification. No model is fitted during preparation.",
                "near_duplicate_limitations": "Cosine >=0.90 hashing prefilter plus exact word-trigram Jaccard >=0.85. Groups with fewer than eight shingles use exact/template matching only. Paraphrases and extensive quoted/edited variants may remain.",
                "dataset_id": digest(json.dumps(sorted((r['id'], r['label'], r['template_hash']) for r in records)))}
    for name, examples in splits.items():
        path = output / (name + ".jsonl")
        with path.open("w", encoding="utf-8") as handle:
            for record in examples:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        manifest["splits"][name] = {"count": len(examples), "class_counts": dict(Counter(str(r["label"]) for r in examples)),
            "source_counts": dict(Counter(r["source"] for r in examples)), "sha256": digest(path.read_bytes())}
    manifest["usable_by_source"] = dict(Counter(r["source"] for r in records))
    write_json(output / "manifest.json", manifest)
    write_json(manifest_path, manifest)
    print(json.dumps({"deduplication": duplicates, "splits": manifest["splits"], "usable_by_source": manifest["usable_by_source"]}, indent=2), flush=True)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, default=ROOT / "data/sources.json")
    parser.add_argument("--raw", type=Path, default=ROOT / "data/raw")
    parser.add_argument("--output", type=Path, default=ROOT / "data/processed/public_email_v1")
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/manifest.json")
    args = parser.parse_args()
    build(args.recipe, args.raw, args.output, args.manifest)
