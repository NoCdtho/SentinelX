import json
import subprocess
from config import MAX_PACKETS


def check_tshark() -> bool:
    """Check if TShark is installed and accessible in PATH."""
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True, #This capture_output stores the output this py. script
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return False
        print("TShark detected.")
        return True
    except (FileNotFoundError, Exception) as exc:
        if not isinstance(exc, FileNotFoundError):
            print(f"Error checking TShark: {exc}")
        return False


def list_interfaces() -> list:
    """Retrieve and display available network capture interfaces."""
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            print("Could not retrieve network interfaces.")
            return []

        interfaces = result.stdout.strip().splitlines()
        print("\nAvailable interfaces:")
        for interface in interfaces:
            print(f"  {interface}")
        return interfaces
    except Exception as exc:
        print(f"Error listing interfaces: {exc}")
        return []


def capture_packets(interface: str, packet_limit: int = MAX_PACKETS) -> list[dict]:
    """Capture packets via TShark and return raw JSON data."""
    print()
    print("Starting packet capture")
    print()
    print(f"Interface   : {interface}")
    print(f"Packet limit: {packet_limit}\n")

    command = [
        "tshark",
        "-i", interface,
        "-c", str(packet_limit),
        "-T", "json"
    ]

    try:
        # this is used to execute above items in list as command in terminal
        process = subprocess.run(
            command, # This are actual command executing on the terminal.
            capture_output=True, # I want this python script to read stdout and stderr. 
            text=True, # convert the raw bytes into human readable format.
            timeout=120 # waiting time.
        )

        if process.returncode != 0:
            print("TShark returned an error:")
            print(process.stderr)
            return []

        if not process.stdout.strip():
            print("No packets captured.")
            return []

        try:
            packets = json.loads(process.stdout) # This is where packets are captured and stored
        except json.JSONDecodeError as exc:
            print(f"Could not parse TShark JSON: {exc}")
            return []

        print(f"\nCaptured {len(packets)} packet(s).")
        return packets[:packet_limit]

    except subprocess.TimeoutExpired:
        print("TShark timed out.")
        return []
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
        return []
    except Exception as exc:
        print(f"Capture error: {exc}")
        return []

