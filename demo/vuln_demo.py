# demo/vuln_demo.py
# Tiny vulnerable Python app for testing Stage-I pipeline
# Safe to run locally

def insecure_eval(user_input):
    # BAD: using eval on user input (predictable vulnerability)
    return eval(user_input)

def main():
    print("=== VulnSage Stage 1 Demo ===")
    inp = input("Enter a number or calculation: ")
    try:
        result = insecure_eval(inp)
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
