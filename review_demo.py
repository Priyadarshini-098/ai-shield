
from combined_pipeline import run_combined_shield
from unittest.mock import patch


def get_result(text):
    # Special demo command: simulate medium risk for testing review options.
    if text.strip() == "/demo-review":
        sample = "Please inspect this simulated medium-risk sample."

        with patch(
            "combined_pipeline.classify_text",
            return_value={
                "risk_level": "medium",
                "score": 0.65,
                "explanation": "Simulated medium risk for the demo.",
                "method": "demo_simulation",
            },
        ):
            return run_combined_shield(sample), True

    return run_combined_shield(text), False


def main():
    print("=" * 55)
    print("          AI SHIELD - HUMAN REVIEW")
    print("Type /demo-review to test the review menu.")
    print("=" * 55)

    while True:
        text = input("\nEnter text (or 'exit' to quit): ").strip()

        if text.lower() == "exit":
            print("Demo closed.")
            break

        if not text:
            print("Please enter some text.")
            continue

        try:
            result, simulated = get_result(text)
        except Exception as error:
            print("Analysis failed safely:", error)
            continue

        print("\n--- SECURITY REPORT ---")
        print("Decision:", result["status"].upper())
        print("Risk:", result["analysis"]["risk_level"])
        print("Explanation:", result["note"])

        if simulated:
            print("NOTE: This is a simulated result, not a real risk assessment.")

        print("\n--- ORIGINAL TEXT (UNCHANGED) ---")
        print(result["original"])

        print("\n--- SAFE PREVIEW ---")
        print(result["preview"])

        if result["status"] == "held_for_review":
            print("\n--- HUMAN REVIEW ---")
            print("1. Approve")
            print("2. Reject")
            print("3. Skip")

            choice = input("Choose 1, 2, or 3: ").strip()

            if choice == "1":
                print("REVIEW RESULT: APPROVED (demo only)")
                print("Approval does not authorize automatic execution.")
            elif choice == "2":
                print("REVIEW RESULT: REJECTED (demo only)")
            elif choice == "3":
                print("REVIEW RESULT: SKIPPED")
            else:
                print("Invalid choice. No decision recorded.")

            print("Original text remains unchanged.")

        elif result["status"] == "blocked":
            print("\nBLOCKED: Manual approval is not offered.")

        else:
            print("\nALLOWED: No manual review requested.")

if __name__ == "__main__":
    main()
