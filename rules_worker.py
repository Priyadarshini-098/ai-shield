"""
rules_worker.py -- Member 3: runs the rule-based detector in a SEPARATE process.

Why: a regex can be made to run for minutes on a crafted input (a "ReDoS" denial-of-service),
and a Python thread cannot interrupt a regex. A separate process CAN be killed on a timeout.
combined_pipeline.py starts this script for large inputs and fails closed if it is too slow.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

if __name__ == "__main__":
    req = json.loads(sys.stdin.read())
    import detector
    sys.stdout.write(json.dumps(detector.analyze(req["text"], source=req["source"])))
