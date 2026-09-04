"""Reproducible offline evaluation of fusion policy engineering behavior."""
from collections import Counter
import argparse
import json
from pathlib import Path
import re
from statistics import mean, median, pstdev

from .analyzers.fusion_engine import calculate_final_risk
from .fusion_policy import CURRENT_FUSION_POLICY, VERDICT_THRESHOLDS
from ml.model_policy import legacy_output_metadata


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "data/calibration/fusion_v2_scenarios.json"
CLASSES = ("LOW", "REVIEW", "HIGH", "CRITICAL")
RANK = {value: index for index, value in enumerate(CLASSES)}
ALLOWED_SOURCES = {"synthetic_controlled_fixture", "repository_safe_sample"}


def load_corpus(path=DEFAULT_CORPUS):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or data.get("fusion_policy") != CURRENT_FUSION_POLICY:
        raise ValueError("Unsupported calibration corpus schema or fusion policy")
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list) or data.get("scenario_count") != len(scenarios):
        raise ValueError("Calibration scenario count is missing or inconsistent")
    ids = set()
    for item in scenarios:
        if not isinstance(item, dict):
            raise ValueError("Each calibration scenario must be an object")
        identity = item.get("id")
        if not isinstance(identity, str) or not re.fullmatch(r"[a-z0-9-]+", identity) or identity in ids:
            raise ValueError("Calibration scenario IDs must be unique safe labels")
        ids.add(identity)
        if item.get("expected_class") not in CLASSES or item.get("source") not in ALLOWED_SOURCES:
            raise ValueError("Unknown engineering target or scenario provenance")
        if not isinstance(item.get("category"), str) or not item["category"]:
            raise ValueError("Every calibration scenario needs a category")
        inputs = item.get("inputs")
        if not isinstance(inputs, dict):
            raise ValueError("Every calibration scenario needs structured inputs")
        for key in ("sender_score", "authentication_score", "ai_score"):
            value = inputs.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 100:
                raise ValueError(f"{identity}: {key} must be numeric from 0 to 100")
        relay = inputs.get("relay_mismatches")
        if isinstance(relay, bool) or not isinstance(relay, int) or not 0 <= relay <= 20:
            raise ValueError(f"{identity}: relay mismatch count is invalid")
        for key in ("reputation_items", "attachment_items"):
            if not isinstance(inputs.get(key), list):
                raise ValueError(f"{identity}: {key} must be a list")
            for evidence in inputs[key]:
                if not isinstance(evidence, dict):
                    raise ValueError(f"{identity}: malformed evidence item")
                for count in ("malicious", "suspicious"):
                    value = evidence.get(count, 0)
                    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
                        raise ValueError(f"{identity}: detection counts must be safe integers")
    return data


def _reputation(items):
    result = {"domains": [], "ips": []}
    for index, item in enumerate(items):
        category = "ips" if item.get("kind") == "ip" else "domains"
        result[category].append({
            "status": "success", "indicator": f"fixture-{index}.invalid",
            "analysis_stats": {
                "malicious": item.get("malicious", 0),
                "suspicious": item.get("suspicious", 0),
            },
        })
    return result


def _attachments(items):
    return [{
        "status": "success", "sha256": f"{index + 1:064x}",
        "analysis_stats": {
            "malicious": item.get("malicious", 0),
            "suspicious": item.get("suspicious", 0),
        },
    } for index, item in enumerate(items)]


def scenario_arguments(item, *, include_bonuses=True):
    inputs = item["inputs"]
    results = inputs["authentication_results"]
    authentication = {
        "risk_score": inputs["authentication_score"],
        "spf": results.get("spf", "unknown"),
        "dkim": results.get("dkim", "unknown"),
        "dmarc": results.get("dmarc", "unknown"),
        "findings": [],
        "evidence_state": inputs["authentication_evidence_state"],
        "evidence_confidence": {
            "source": inputs.get("authentication_evidence_source", "configured_receiver"),
        },
    }
    return {
        "sender_identity": {"risk_score": inputs["sender_score"], "findings": []},
        "authentication": authentication,
        "relay_trace": {"hops": [
            {"chain_status": "MISMATCH"} for _ in range(inputs["relay_mismatches"])
        ]} if include_bonuses else {"hops": []},
        "ai_analysis": {
            "phishing_probability": inputs["ai_score"],
            "verdict": "SUPPORTING SIGNAL",
            **legacy_output_metadata(),
        },
        "reputation": _reputation(inputs["reputation_items"]) if include_bonuses else {},
        "attachment_reputation": _attachments(inputs["attachment_items"]) if include_bonuses else [],
    }


def outcome_class(assessment):
    verdict = assessment["verdict"]
    if verdict == "LIKELY SAFE":
        return "LOW"
    if verdict == "HIGH RISK":
        return "HIGH"
    if verdict == "CRITICAL":
        return "CRITICAL"
    return "REVIEW"


def evaluate_scenario(item):
    result = calculate_final_risk(**scenario_arguments(item))
    without_bonuses = calculate_final_risk(**scenario_arguments(item, include_bonuses=False))
    contributions = result["contributions"]
    displayed = sum(contributions[key] for key in (
        "sender_identity", "authentication", "reputation", "attachment", "relay", "ai"
    ))
    if abs(displayed - contributions["total_before_rounding_and_cap"]) > 1e-9:
        raise AssertionError("Displayed evidence contributions do not sum to the raw total")
    if abs(displayed + contributions["rounding_and_cap_adjustment"] - result["risk_score"]) > 1e-9:
        raise AssertionError("Contribution adjustment does not reconcile the final score")
    actual = outcome_class(result)
    expected = item["expected_class"]
    component_values = {
        key: contributions[key] for key in (
            "sender_identity", "authentication", "reputation", "attachment", "relay", "ai"
        )
    }
    dominant = max(component_values, key=lambda key: (component_values[key], key))
    if not component_values[dominant]:
        dominant = "none"
    distances = {str(value): abs(result["risk_score"] - value)
                 for value in VERDICT_THRESHOLDS.values()}
    return {
        "id": item["id"], "category": item["category"], "source": item["source"],
        "expected_class": expected, "actual_class": actual,
        "score": result["risk_score"], "verdict": result["verdict"],
        "classification": (
            "match" if actual == expected else
            "false_high" if RANK[actual] > RANK[expected] else "false_low"
        ),
        "dominant_contribution": dominant,
        "contributions": contributions,
        "bonus_score_effect": result["risk_score"] - without_bonuses["risk_score"],
        "nearest_threshold_distance": min(distances.values()),
        "reasons": result["reasons"],
        "fusion_policy_version": result["fusion_policy_version"],
        "ai_numeric_contribution": result["ai_numeric_contribution"],
    }


def _stats(values):
    return {
        "minimum": min(values), "maximum": max(values),
        "mean": round(mean(values), 4), "median": median(values),
        "population_stddev": round(pstdev(values), 4),
    }


def _score_bucket(score):
    if score < 20:
        return "0-19"
    if score < 40:
        return "20-39"
    if score < 60:
        return "40-59"
    if score < 80:
        return "60-79"
    return "80-100"


def _signal_sensitivity(name):
    rows = []
    for value in range(0, 101, 10):
        sender = value if name == "sender_identity" else 0
        authentication = value if name == "authentication" else 0
        result = calculate_final_risk(
            {"risk_score": sender},
            {"risk_score": authentication, "findings": []},
            {"hops": []},
            {"phishing_probability": 100, **legacy_output_metadata()},
        )
        rows.append({"input": value, "score": result["risk_score"],
                     "verdict": result["verdict"]})
    return rows


def _bonus_sensitivity(kind):
    detections = ((0, 0), (0, 1), (1, 0), (2, 1), (4, 0), (5, 0))
    rows = []
    for malicious, suspicious in detections:
        item = {"malicious": malicious, "suspicious": suspicious}
        kwargs = {
            "sender_identity": {"risk_score": 0},
            "authentication": {"risk_score": 0, "findings": []},
            "relay_trace": {"hops": []},
            "ai_analysis": {"phishing_probability": 100, **legacy_output_metadata()},
            "reputation": _reputation([item]) if kind == "reputation" else {},
            "attachment_reputation": _attachments([item]) if kind == "attachment" else [],
        }
        result = calculate_final_risk(**kwargs)
        rows.append({
            "malicious": malicious, "suspicious": suspicious,
            "raw_detection_score": min(100, malicious * 20 + suspicious * 10),
            "bonus": result[kind + "_bonus"], "final_score": result["risk_score"],
        })
    return rows


def build_report(corpus=None):
    corpus = corpus or load_corpus()
    outcomes = [evaluate_scenario(item) for item in corpus["scenarios"]]
    scores = [item["score"] for item in outcomes]
    false_high = [item["id"] for item in outcomes if item["classification"] == "false_high"]
    false_low = [item["id"] for item in outcomes if item["classification"] == "false_low"]
    near = [item["id"] for item in outcomes if item["nearest_threshold_distance"] <= 3]
    confusion = {
        expected: {actual: sum(
            item["expected_class"] == expected and item["actual_class"] == actual
            for item in outcomes
        ) for actual in CLASSES}
        for expected in CLASSES
    }
    return {
        "report_schema_version": 1,
        "corpus_id": corpus["corpus_id"],
        "scenario_count": len(outcomes),
        "policy_evaluated": CURRENT_FUSION_POLICY,
        "calibration_claim": "Engineering scenario evaluation only; not statistical probability calibration.",
        "weights": {
            "sender_identity": 6 / 13,
            "authentication": 7 / 13,
            "unvalidated_ai": 0,
            "sum": 1,
        },
        "verdict_thresholds": dict(VERDICT_THRESHOLDS),
        "score_statistics": _stats(scores),
        "score_distribution": dict(sorted(Counter(_score_bucket(value) for value in scores).items())),
        "verdict_distribution": dict(sorted(Counter(item["verdict"] for item in outcomes).items())),
        "target_distribution": dict(sorted(Counter(item["expected_class"] for item in outcomes).items())),
        "actual_class_distribution": dict(sorted(Counter(item["actual_class"] for item in outcomes).items())),
        "classification_distribution": dict(sorted(Counter(item["classification"] for item in outcomes).items())),
        "confusion_matrix": confusion,
        "false_high": false_high,
        "false_low": false_low,
        "near_threshold": near,
        "dominant_evidence": dict(sorted(Counter(item["dominant_contribution"] for item in outcomes).items())),
        "bonus_effect_statistics": _stats([item["bonus_score_effect"] for item in outcomes]),
        "sensitivity": {
            "sender_identity": _signal_sensitivity("sender_identity"),
            "authentication": _signal_sensitivity("authentication"),
            "reputation": _bonus_sensitivity("reputation"),
            "attachment": _bonus_sensitivity("attachment"),
            "relay": [
                {"mismatches": count, "bonus": calculate_final_risk(
                    {"risk_score": 0}, {"risk_score": 0, "findings": []},
                    {"hops": [{"chain_status": "MISMATCH"}] * count},
                    {"phishing_probability": 100, **legacy_output_metadata()},
                )["relay_bonus"]}
                for count in (0, 1, 2, 5)
            ],
        },
        "duplicate_bonus_checks": {
            "reputation_single": next(x["score"] for x in outcomes if x["id"] == "malicious-reputation"),
            "reputation_repeated": next(x["score"] for x in outcomes if x["id"] == "duplicate-malicious-reputation"),
            "attachment_single": next(x["score"] for x in outcomes if x["id"] == "malicious-attachment-reputation"),
            "attachment_repeated": next(x["score"] for x in outcomes if x["id"] == "duplicate-malicious-attachment"),
            "relay_single": next(x["score"] for x in outcomes if x["id"] == "relay-mismatch"),
            "relay_repeated": next(x["score"] for x in outcomes if x["id"] == "repeated-relay-mismatch"),
        },
        "outcomes": outcomes,
        "decision": {
            "weights": "KEEP",
            "bonuses": "KEEP",
            "thresholds": "KEEP",
            "reason": (
                "The corpus is controlled engineering evidence, not an independent labeled inbox sample. "
                "V2 is monotonic, prevents any one base component from reaching HIGH, caps each bonus family, "
                "and does not double count repeats. Observed misses identify evidence-model gaps and ambiguous "
                "single-source targets; changing numeric policy on this corpus would overfit those assumptions."
            ),
        },
        "limitations": [
            "Scenario targets are engineering judgments rather than real-world ground truth.",
            "Raw URL suspiciousness has no direct numeric input unless reputation evidence is available.",
            "A single SPF or DKIM failure can remain below the first numeric threshold.",
            "Strong reputation or attachment evidence is capped at 20 points and cannot alone produce HIGH.",
            "Authentication is parsed reported evidence, not independent cryptographic verification.",
            "Score distributions are corpus-composition dependent and are not performance probabilities.",
        ],
    }


def write_report(report, path):
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8", newline="\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    report = build_report(load_corpus(args.corpus))
    if args.output:
        write_report(report, args.output)
    else:
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
