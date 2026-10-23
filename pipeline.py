from detector import analyze
from protection import review_gate

def run_shield(text):
    analysis = analyze(text)
    gate = review_gate(text, analysis)
    return {"analysis": analysis, "gate": gate}
