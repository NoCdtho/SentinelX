import json
import subprocess
from config import MAX_PACKETS


def check_tshark() -> bool:
    """Check if TShark is installed and accessible in PATH."""
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            return False
        print("TShark detected.")
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


def capture_packets(interface: str, packet_limit: int = MAX_PACKETS) -> list:
    """Capture packets via TShark and return raw JSON data."""
    print()
    print("=" * 60)
    print("Starting packet capture")
    print("=" * 60)
    print(f"Interface   : {interface}")
    print(f"Packet limit: {packet_limit}\n")

    command = [
        "tshark",
        "-i", interface,
        "-c", str(packet_limit),
        "-T", "json"
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        if process.returncode != 0:
            print("TShark returned an error:")
            print(process.stderr)
            return []

        if not process.stdout.strip():
            print("No packets captured.")
            return []

        try:
            packets = json.loads(process.stdout)
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