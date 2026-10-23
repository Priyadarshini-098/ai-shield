import json
from detector import analyze
from pipeline import run_shield

# The simple phrase list from your first demo.py
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

def main():
    with open("benchmark_data.json", encoding="utf-8") as f:
        data = json.load(f)

    baseline = [baseline_detect(d["text"]) for d in data]
    detector = [analyze(d["text"])["risk_level"] != "low" for d in data]
    workflow = [run_shield(d["text"])["gate"]["status"] == "held_for_review" for d in data]

    results = {
        "baseline": metrics(data, baseline),
        "ai_shield_detector": metrics(data, detector),
        "full_workflow": metrics(data, workflow),
    }

    print(f"{'Setup':<22}{'Detection':<12}{'False alarms':<15}{'Precision'}")
    for name, m in results.items():
        print(f"{name:<22}{m['detection_rate']:<12}{m['false_positive_rate']:<15}{m['precision']}")

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