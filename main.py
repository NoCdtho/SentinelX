from tshark import check_tshark, list_interfaces
from pipeline import analysis


def print_help():
    print("\nAvailable commands:")
    print("  start       Start packet capture and analysis")
    print("  interfaces  List TShark network interfaces")
    print("  help        Show this help")
    print("  exit        Exit program\n")


def main():
    print()
    print("=" * 60)
    print("AI NETWORK PACKET ANALYSIS TOOL")
    print("=" * 60)
    print_help()

    while True:
        try:
            command = input("\ncyber-analyzer> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        if command == "start":
            analysis()
        elif command == "interfaces":
            if check_tshark():
                list_interfaces()
            else:
                print("TShark is not installed or is not available in PATH.")
        elif command == "help":
            print_help()
        elif command in {"exit", "quit"}:
            print("Goodbye.")
            break
        elif command == "":
            continue
        else:
            print(f"Unknown command: {command}")
            print("Type 'help' to see available commands.")


if __name__ == "__main__":
    main()