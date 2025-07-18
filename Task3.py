import re
def assess_password_strength(password):
    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9\s]", password))

    strength = "weak"
    feedback = []

    if length < 8:
        feedback.append("Password is too short. Max to Max 8 characters.")
    elif length < 12:
        strength = "moderate"
    else:
        strength = "strong"

    if not has_upper:
        feedback.append("Add uppercase letters.")
    if not has_lower:
        feedback.append("Add lowercase letters.")
    if not has_digit:
        feedback.append("Add numbers.")
    if not has_special:
        feedback.append("Add special characters (e.g., !, @, #, $).")

    # Add checks for common patterns and banned passwords (optional)

    return strength, feedback

def main():
    print("Welcome to the Password Strength Checker!")
    print("You can enter a password to check its strength.")
    while True:
        password = input("Enter a password (or 'exit' to quit): ")
        if password.lower() == 'exit':
            break

        strength, feedback = assess_password_strength(password)

        print(f"Password strength: {strength}")
        if feedback:
            print("Feedback:")
            for message in feedback:
                print(f"- {message}")
        print("-" * 20)


if __name__ == "__main__":
    main()