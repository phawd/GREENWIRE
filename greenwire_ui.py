import os
import subprocess

def display_menu():
    """
    Display the main menu for the GREENWIRE project.
    """
    print("===================================")
    print("  Operation GREENWIRE - Main Menu  ")
    print("===================================")
    print("1. Issue DDA-Compliant JCOP Card")
    print("2. Perform Dry Runs")
    print("3. Fuzz JCOP APDU Commands")
    print("4. Verify EMV Transactions")
    print("5. Authenticate via CVM")
    print("6. Test NFC4 Wireless Operations")
    print("7. Exit")
    print("===================================")

def handle_choice(choice):
    """
    Handle the user's menu choice.
    """
    if choice == "1":
        card_type = input("Enter card type (visa, mc, amex, etc.): ")
        lun = input("Enter LUN (leave blank for random): ")
        key_data = input("Enter key data for DDA issuance: ")
        subprocess.run(["python", "greenwire-brute.py", "--mode", "issue-dda", "--type", card_type, "--lun", lun, "--key_data", key_data])
    elif choice == "2":
        iterations = input("Enter number of dry runs: ")
        subprocess.run(["python", "greenwire-brute.py", "--mode", "dry-run", "--count", iterations])
    elif choice == "3":
        fuzz_pattern = input("Enter APDU fuzz pattern: ")
        subprocess.run(["python", "greenwire-brute.py", "--mode", "fuzz-jcop", "--fuzz_pattern", fuzz_pattern])
    elif choice == "4":
        emv_command = input("Enter EMV command for transaction verification: ")
        subprocess.run(["python", "greenwire-brute.py", "--mode", "verify-transaction", "--emv_command", emv_command])
    elif choice == "5":
        auth_data = input("Enter authentication data for CVM: ")
        subprocess.run(["python", "greenwire-brute.py", "--mode", "cvm", "--auth", auth_data])
    elif choice == "6":
        nfc_data = input("Enter data for NFC4 wireless test: ")
        subprocess.run(["python", "greenwire-brute.py", "--mode", "nfc4", "--nfc_data", nfc_data])
    elif choice == "7":
        print("Exiting Operation GREENWIRE. Goodbye!")
        exit()
    else:
        print("Invalid choice. Please try again.")

def main():
    """
    Main function to run the user interface.
    """
    while True:
        display_menu()
        choice = input("Enter your choice: ")
        handle_choice(choice)

if __name__ == "__main__":
    main()
