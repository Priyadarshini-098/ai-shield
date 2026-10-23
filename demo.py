
from combined_pipeline import run_combined_shield


def main():
    print("=" * 50)
    print("           AI SHIELD DEMO")
    print("   Prompt Injection Protection System")
    print("=" * 50)

    while True:
        print("\nEnter text to check (or type 'exit' to quit):")
        text = input("> ")

        if text.strip().lower() == "exit":
            print("AI Shield demo closed.")
            break

        if not text.strip():
            print("Please enter some text.")
            continue

        try:
            result = run_combined_shield(text)

            print("\n--- SECURITY REPORT ---")
            print("Decision:", result["status"].upper())
            print("Risk level:", result["analysis"]["risk_level"])
            print("Explanation:", result["note"])

            print("\n--- SAFE PREVIEW ---")
            print(result["preview"])

            print("\n--- ORIGINAL TEXT ---")
            print(result["original"])

        except Exception as error:
            print("Could not analyze the text:", error)


if __name__ == "__main__":
    main()
