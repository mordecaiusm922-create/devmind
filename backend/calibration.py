from __future__ import annotations

from dataclasses import dataclass
from typing import Any


GOOD_OUTCOMES = {
    "merged_without_regression",
    "merged",
    "fixed",
    "verified",
    "passed",
    "no_regression",
    "safe",
    "accepted",
}

BAD_OUTCOMES = {
    "regression",
    "security_incident",
    "exploit",
    "rollback",
    "failed",
    "unsafe",
    "vulnerable",
    "incident",
    "production_failure",
    "blocked_after_review",
}


@dataclass(frozen=True)
class CalibrationPair:
    entity: str
    predicted: float
    observed: int
    prediction_event_type: str
    outcome: str


def expected_calibration_error(repo: str, bins: int = 10) -> dict[str, Any]:
    from memory import load_events

    return expected_calibration_error_from_events(load_events(repo), bins=bins, repo=repo)


def expected_calibration_error_from_events(
    events: list[dict[str, Any]],
    *,
    bins: int = 10,
    repo: str | None = None,
) -> dict[str, Any]:
    pairs = _pair_predictions_with_outcomes(events)
    bins = max(2, min(20, int(bins or 10)))

    if not pairs:
        return {
            "repo": repo,
            "n": 0,
            "ece": None,
            "brier": None,
            "bins": [],
            "status": "insufficient_outcomes",
            "message": "Record real PR outcomes with POST /outcome to calibrate probabilities.",
        }

    buckets = [
        {
            "bin": i,
            "range": [round(i / bins, 3), round((i + 1) / bins, 3)],
            "n": 0,
            "avg_confidence": 0.0,
            "observed_rate": 0.0,
            "gap": 0.0,
        }
        for i in range(bins)
    ]

    for pair in pairs:
        idx = min(bins - 1, int(pair.predicted * bins))
        bucket = buckets[idx]
        bucket["n"] += 1
        bucket["avg_confidence"] += pair.predicted
        bucket["observed_rate"] += pair.observed

    ece = 0.0
    total = len(pairs)
    for bucket in buckets:
        if bucket["n"] == 0:
            continue
        bucket["avg_confidence"] = round(bucket["avg_confidence"] / bucket["n"], 4)
        bucket["observed_rate"] = round(bucket["observed_rate"] / bucket["n"], 4)
        bucket["gap"] = round(abs(bucket["avg_confidence"] - bucket["observed_rate"]), 4)
        ece += (bucket["n"] / total) * bucket["gap"]

    brier = sum((pair.predicted - pair.observed) ** 2 for pair in pairs) / total
    return {
        "repo": repo,
        "n": total,
        "ece": round(ece, 4),
        "brier": round(brier, 4),
        "bins": buckets,
        "status": "ok" if total >= 20 else "low_sample",
        "pairs_preview": [
            {
                "entity": pair.entity,
                "predicted": pair.predicted,
                "observed": pair.observed,
                "outcome": pair.outcome,
            }
            for pair in pairs[-10:]
        ],
    }


def calibrate_probability(repo: str, probability: float, bins: int = 10) -> dict[str, Any]:
    summary = expected_calibration_error(repo, bins=bins)
    p = _clamp01(probability)
    if not summary.get("bins") or not summary.get("n"):
        return {"probability": round(p, 4), "raw_probability": round(p, 4), "method": "identity", "summary": summary}

    idx = min(len(summary["bins"]) - 1, int(p * len(summary["bins"])))
    bucket = summary["bins"][idx]
    if bucket.get("n", 0) < 3:
        calibrated = p
        method = "identity_low_bin_sample"
    else:
        observed = float(bucket.get("observed_rate", p))
        calibrated = 0.70 * p + 0.30 * observed
        method = "bin_observed_rate_blend"

    return {
        "probability": round(_clamp01(calibrated), 4),
        "raw_probability": round(p, 4),
        "method": method,
        "bin": bucket,
        "summary": {
            "repo": summary.get("repo"),
            "n": summary.get("n"),
            "ece": summary.get("ece"),
            "brier": summary.get("brier"),
            "status": summary.get("status"),
        },
    }


def _pair_predictions_with_outcomes(events: list[dict[str, Any]]) -> list[CalibrationPair]:
    outcomes_by_entity: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("event_type") != "outcome":
            continue
        outcome = _normalize_outcome(event.get("outcome") or event.get("label"))
        observed = _observed_failure(outcome)
        if observed is None:
            continue
        outcomes_by_entity[str(event.get("entity") or "")] = {**event, "_observed": observed, "_outcome": outcome}

    pairs: list[CalibrationPair] = []
    for event in events:
        entity = str(event.get("entity") or "")
        if entity not in outcomes_by_entity:
            continue
        predicted = _prediction_probability(event)
        if predicted is None:
            continue
        outcome = outcomes_by_entity[entity]
        pairs.append(
            CalibrationPair(
                entity=entity,
                predicted=predicted,
                observed=int(outcome["_observed"]),
                prediction_event_type=str(event.get("event_type") or "unknown"),
                outcome=str(outcome["_outcome"]),
            )
        )

    return pairs


def _prediction_probability(event: dict[str, Any]) -> float | None:
    metadata = event.get("metadata") or {}
    for key in ("p_exploit", "probability", "predicted_probability", "risk_probability"):
        if key in metadata:
            return _clamp01(_safe_float(metadata[key]))

    if "risk" in event and event.get("risk") is not None:
        risk = _safe_float(event.get("risk"))
        return _clamp01(risk / 100.0 if risk > 1 else risk)

    risk_obj = metadata.get("risk") or {}
    if isinstance(risk_obj, dict):
        if "p_exploit" in risk_obj:
            return _clamp01(_safe_float(risk_obj["p_exploit"]))
        if "score" in risk_obj:
            return _clamp01(_safe_float(risk_obj["score"]) / 100.0)

    return None


def _normalize_outcome(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _observed_failure(outcome: str) -> int | None:
    if outcome in GOOD_OUTCOMES or any(marker in outcome for marker in ("merged_without_regression", "no_regression", "passed", "fixed", "safe")):
        return 0
    if outcome in BAD_OUTCOMES or any(marker in outcome for marker in ("regression", "incident", "rollback", "exploit", "failed")):
        return 1
    if any(marker in outcome for marker in ("merged", "accepted")):
        return 0
    return None


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))
