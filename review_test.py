
from unittest.mock import patch
from combined_pipeline import run_combined_shield

text = "Please inspect this sample."

with patch(
    "combined_pipeline.classify_text",
    return_value={
        "risk_level": "medium",
        "score": 0.65,
        "explanation": "Suspicious content needs human review.",
        "method": "demo",
    },
):
    result = run_combined_shield(text)

print("Decision:", result["status"])
print("Risk:", result["analysis"]["risk_level"])
print("Original preserved:", result["original"] == text)
print("Preview:", result["preview"])
