"""
A simple, reusable menu builder for console applications.
"""

class MenuBuilder:
    def __init__(self, title, prompt="Select an option:"):
        self.title = title
        self.prompt = prompt
        self.items = []
        self.exit_option = "Exit"

    def add_option(self, label, action=None, is_exit=False):
        """Adds a menu option."""
        if is_exit:
            self.exit_option = label
        else:
            self.items.append({"label": label, "action": action})
        return self

    def show(self):
        """Displays the menu and handles user selection."""
        while True:
            print("\n" + "=" * 40)
            print(f"  {self.title}")
            print("=" * 40)

            for i, item in enumerate(self.items, 1):
                print(f"  {i}. {item['label']}")

            print(f"\n  0. {self.exit_option}")
            print("-" * 40)

            try:
                choice = input(f"{self.prompt} ")
                if not choice:
                    continue

                choice = int(choice)

                if choice == 0:
                    return None  # Exit signal

                if 1 <= choice <= len(self.items):
                    selected_item = self.items[choice - 1]
                    action = selected_item.get("action")
                    if action:
                        # Execute the action and check if it returns a signal to exit
                        result = action()
                        if result == "exit_menu":
                            return None
                    else:
                        print("No action defined for this option.")
                    # Pause to allow user to see output before re-displaying menu
                    input("\nPress Enter to continue...")
                else:
                    print("Invalid choice, please try again.")

            except ValueError:
                print("Invalid input, please enter a number.")
            except KeyboardInterrupt:
                print("\nMenu interrupted. Exiting.")
                return None
