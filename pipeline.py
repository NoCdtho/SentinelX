import sys
import time
from config import MAX_PACKETS, TSHARK_INTERFACE, validate_configuration
from capture import check_tshark, capture_packets
from parser import parse_packet
from analyzer import analyze_packet_with_llm
from notion_client import create_notion_page


def run_analysis():
    
    # This functions ensures all the required variables are set.
    validate_configuration()

    # Checks if tshaark is present or not. 
    if not check_tshark():
        print("\nTShark was not found. Install Wireshark/TShark and add tshark to PATH.")
        sys.exit(1)

    print()
    print("AGENTIC NETWORK PACKET ANALYZER")

    # Here network packets are being captured
    packets_raw = capture_packets(TSHARK_INTERFACE, MAX_PACKETS)
    if not packets_raw:
        print("No packets available for analysis.")
        return

    # Parse Packets
    print()
    print("Parsing packets")
    print()

    parsed_packets = []
    for index, raw_packet in enumerate(packets_raw, start=1):
        packet = parse_packet(raw_packet, index)
        parsed_packets.append(packet)
        print(f"[{index}/{len(packets_raw)}] {packet['protocol_stack']} {packet['source_ip']} -> {packet['destination_ip']}")

    # LLM Security Analysis
    print()
    print("LLM SECURITY ANALYSIS")
    print()

    analyzed_packets = []
    for index, packet in enumerate(parsed_packets, start=1):
        print(f"\nAnalyzing packet {index}/{len(parsed_packets)}...")
        analysis = analyze_packet_with_llm(packet)
        analyzed_packets.append({"packet": packet, "analysis": analysis})
        print(f"Risk: {analysis.get('risk_level', 'Unknown')}")

        if index < len(parsed_packets):
            time.sleep(0.5)

    # Export to Notion
    print()
    print("=" * 60)
    print("CREATING NOTION DOCUMENT")
    print("=" * 60)

    create_notion_page(analyzed_packets)