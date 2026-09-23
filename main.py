from tools.tshark import check_tshark, list_interfaces
from pipeline import analysis
import os
from dotenv import load_dotenv, set_key


# This funtion is used to load and set the variables from env files
load_dotenv()

env_path = ".env"

def print_help():
    print("\nAvailable commands:")
    print("  start       Start packet capture and analysis")
    print("  interfaces  List TShark network interfaces")
    print("  help        Show this help")
    print("  exit        Exit program\n")


def main():
    print()
    print("AI NETWORK PACKET ANALYSIS TOOL")
    print_help()
    print()
    print("\nSelect interface either wi-fi or ethernet.........")
    print()
    while True:
        try:
            command = input("\ncyber-analyzer> ").strip().lower()
           
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        if command == "ethernet":
            set_key(env_path, "TSHARK_INTERFACE", command)
            updated_interfaces = os.getenv("TSHARK_INTERFACE")
            print(f"Now the interface is updated  to {updated_interfaces}")
        elif command == "start":
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


main()