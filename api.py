
from flask import Flask, request, jsonify
from flask_cors import CORS

from pipeline import run_shield

app = Flask(__name__)

# Allow your GitHub Pages website to call this API.
# Restrict this to your exact website origin before production.
CORS(app)

@app.get("/")
def health_check():
    return jsonify({
        "status": "online",
        "service": "AI Shield API"
    })

@app.post("/analyze")
def analyze_prompt():
    data = request.get_json(silent=True) or {}
    text = data.get("text")

    if not isinstance(text, str) or not text.strip():
        return jsonify({"error": "Please provide prompt text."}), 400

    if len(text) > 20000:
        return jsonify({"error": "Prompt is too long."}), 413

    try:
        result = run_shield(text)
        return jsonify(result)
    except Exception:
        app.logger.exception("AI Shield analysis failed")
        return jsonify({
            "error": "Analysis failed. Please try again."
        }), 500
