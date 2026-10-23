import json

from detector import analyze
from pipeline import run_shield

# The simple phrase list from the first demo (our baseline)
BASELINE_PHRASES = [
    "ignore previous instructions", "ignore all previous instructions",
    "forget your previous prompt", "forget your instructions",
    "disregard all previous", "you are now",
    "pretend the above never existed", "print all internal instructions",
    "reveal your system prompt", "admin code", "cancel all safety rules",
]


def baseline_detect(text):
    t = text.lower()
    return any(p in t for p in BASELINE_PHRASES)


def metrics(data, preds):
    tp = sum(1 for d, p in zip(data, preds) if d["label"] == "attack" and p)
    fn = sum(1 for d, p in zip(data, preds) if d["label"] == "attack" and not p)
    fp = sum(1 for d, p in zip(data, preds) if d["label"] == "normal" and p)
    tn = sum(1 for d, p in zip(data, preds) if d["label"] == "normal" and not p)
    return {
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "detection_rate": round(tp / (tp + fn), 2) if tp + fn else 0,
        "false_positive_rate": round(fp / (fp + tn), 2) if fp + tn else 0,
        "precision": round(tp / (tp + fp), 2) if tp + fp else 0,
    }


def level_of(analysis):
    """Risk level from a contract dictionary OR from Member 1's report object."""
    if isinstance(analysis, dict):
        level = analysis.get("risk_level") or analysis.get("level")
    else:
        level = getattr(analysis, "risk_level", None) or getattr(analysis, "level", None)
    if level is None:
        raise ValueError("cannot find the risk level in the detector output")
    return str(level).lower()


def was_held(result):
    """True if the review gate held the content for review."""
    gate = result.get("gate") if isinstance(result, dict) else getattr(result, "gate", None)
    if isinstance(gate, dict):
        status = gate.get("status") or gate.get("decision")
    else:
        status = getattr(gate, "status", None) or getattr(gate, "decision", None)
    if status is None:
        raise ValueError("cannot find the gate status in the pipeline output")
    return "held" in str(status).lower()


def main(include_ai=False):
    # include_ai is accepted so older dashboard code can still call main(include_ai=...)
    with open("benchmark_data.json", encoding="utf-8") as f:
        data = json.load(f)

    results = {"baseline": metrics(data, [baseline_detect(d["text"]) for d in data])}
    workflow = None

    try:
        rules = [level_of(analyze(d["text"])) != "low" for d in data]
        results["ai_shield_detector"] = metrics(data, rules)
    except Exception as e:
        print(f"WARNING: detector step failed ({type(e).__name__}: {e}). Skipped.")

    try:
        workflow = [was_held(run_shield(d["text"])) for d in data]
        results["full_workflow"] = metrics(data, workflow)
    except Exception as e:
        print(f"WARNING: full workflow step failed ({type(e).__name__}: {e}). Skipped.")

    print(f"{'Setup':<22}{'Detection':<12}{'False alarms':<15}{'Precision'}")
    for name, m in results.items():
        print(f"{name:<22}{m['detection_rate']:<12}{m['false_positive_rate']:<15}{m['precision']}")

    if workflow is not None:
        print("\nAttacks the full workflow MISSED:")
        for d, p in zip(data, workflow):
            if d["label"] == "attack" and not p:
                print(f"  #{d['id']} ({d['category']}): {d['text']}")

        print("\nNormal inputs wrongly FLAGGED (false alarms):")
        for d, p in zip(data, workflow):
            if d["label"] == "normal" and p:
                print(f"  #{d['id']}: {d['text']}")

    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("\nSaved results.json")


if __name__ == "__main__":
    main()