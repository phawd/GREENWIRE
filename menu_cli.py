"""Minimal menu-driven interface for the GREENWIRE toolkit."""

import logging
from greenwire import GreenwireSuperTouch


def display_menu():
    """Print the available command-line menu options."""
    print("\nGREENWIRE CLI Menu")
    print("1. SUPERTOUCH Operation")
    print("2. Execute JavaCard .cap Tests")
    print("3. Exit")


def execute_javacard_tests():
    """Run a series of JavaCard .cap tests using the SUPERTOUCH tool."""
    logging.info("Starting JavaCard .cap tests...")
    supertouch_tool = GreenwireSuperTouch()

    # Example CAP file and AIDs
    cap_file = "path/to/capfile"
    package_aid = "A000000003000000"
    applet_aid = "A000000003000001"

    for i in range(100):
        try:
            logging.info(f"Executing test {i + 1}...")
            supertouch_tool.supertouch(cap_file, package_aid, applet_aid)
        except Exception as e:
            logging.error(f"Test {i + 1} failed: {e}")

    logging.info("JavaCard .cap tests completed.")


def main():
    """Entry point for the interactive CLI menu."""
    logging.basicConfig(
        level=logging.INFO,
        filename="greenwire_cli_log.txt",
        filemode='a',
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    while True:
        display_menu()
        choice = input("Enter your choice: ")

        if choice == "1":
            cap_file = input("Enter CAP file path: ")
            package_aid = input("Enter Package AID: ")
            applet_aid = input("Enter Applet AID: ")
            supertouch_tool = GreenwireSuperTouch()
            supertouch_tool.supertouch(cap_file, package_aid, applet_aid)
        elif choice == "2":
            execute_javacard_tests()
        elif choice == "3":
            print("Exiting GREENWIRE CLI. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
