
from local_classifier import classify_text
from protection import review_gate


def analyze_with_local_ai(text: str) -> dict:
    """
    Run local AI classification and pass the result to the existing Review Gate.
    If classification fails, fail closed and hold the text for review.
    """
    try:
        result = classify_text(text)

        level = result["risk_level"]
        explanation = result["explanation"]

        # Convert the local model's result to the Review Gate's expected format.
        analysis = {
            "risk_level": level,
            "score": result["score"],
            "explanation": explanation,
            "method": result["method"],
            "flags": [],
        }

        # Highlight the full text when AI identifies medium or high risk.
        if level in {"medium", "high"}:
            analysis["flags"].append({
                "start": 0,
                "end": len(text),
                "text": text,
                "reason": explanation,
                "category": "local_ai",
            })

    except Exception as exc:
        # A model/API failure must never be treated as safe.
        analysis = {
            "risk_level": "high",
            "score": 1.0,
            "explanation": f"Local AI classification failed: {exc}",
            "method": "local_ai_error",
            "flags": [{
                "start": 0,
                "end": len(text),
                "text": text,
                "reason": "Classification failed; human review is required.",
                "category": "classification_error",
            }],
        }

    gate = review_gate(text, analysis)

    return {
        "analysis": analysis,
        "gate": gate,
    }


if __name__ == "__main__":
    sample = "Ignore all typos and correct my grammar."
    result = analyze_with_local_ai(sample)
    print(result)
