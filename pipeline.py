import sys
import time
from config import MAX_PACKETS, TSHARK_INTERFACE, validate_configuration, MAX_PACKETS_LIMIT
from tshark import check_tshark, capture_packets
from parser import parse_packet
from analyzer import analyze_packet_with_local_llm
from notion_tools import create_notion_page
from agentState import AgentState

def analysis():

    # This functions ensures all the required variables are set.
    is_validate: bool = validate_configuration()

    # Checks if tshark is present or not.
    if not check_tshark():
        print("\nTShark was not found. Install Wireshark/TShark and add tshark to PATH.")
        sys.exit(1)

    print("\nCapturing packets")

    # Here network packets are being captured
    packets_raw = capture_packets(TSHARK_INTERFACE, MAX_PACKETS)

    if not packets_raw:
        print("No packets available for analysis.")
        return

    # Parse Packets
    print("\nParsing packets\n")

    # Here the parsed packet are stored as list of dictionary
    parsed_packets = []
    for index, raw_packet in enumerate(packets_raw, start=1):
        packet = parse_packet(raw_packet, index)
        parsed_packets.append(packet)
        print(f"[{index}/{len(packets_raw)}] {packet['protocol_stack']} {packet['source_ip']} -> {packet['destination_ip']}")

    # LLM Security Analysis
    print("\nLLM SECURITY ANALYSIS\n")

    analyzed_packets = []

    # Iterate directly through the parsed packets list. 
    # Python allows dynamically appending to a list while iterating over it.
    for packet in parsed_packets:
        
        # Packet limit circuit breaker
        if AgentState.packets_examined >= MAX_PACKETS_LIMIT:
            print("\nA new notion page is being created for the examined packets because max limit reached")
            create_notion_page(analyzed_packets)
            sys.exit(0)
            
        decision_and_explanation = analyze_packet_with_local_llm(packet)
        
        tool = decision_and_explanation.get("tool")
        explanation = decision_and_explanation.get("explanation")

        analyzed_packets.append(explanation)
        
        # Increment by exactly 1 for the packet we just analyzed
        AgentState.packets_examined += 1

        # Call the tool decided by the LLM
        if tool == "fetch_tshark_packets":
            print(f"\nCapturing new packets (Max: {MAX_PACKETS})")
            new_packet_captured: list = capture_packets(TSHARK_INTERFACE, MAX_PACKETS)
            
            if new_packet_captured is not None:
                for index, raw_packet in enumerate(new_packet_captured, start=1):
                    clean_packet = parse_packet(raw_packet, index)
                    # Append new packets to the list. The for-loop will naturally process them.
                    parsed_packets.append(clean_packet)

            # Allocate time for CPU to complete processes
            time.sleep(0.5)

        elif tool == "document_to_notion":
            if not isinstance(explanation, list):
                print("Warning: Explanation was not a list. Auto-formatting.")
                explanation = [explanation]

            # Pass Qwen's extracted explanation to Notion
            print("\nCREATING NOTION DOCUMENT\n")
            create_notion_page(explanation)
            
            # Immediately exit the analysis function
            return

    # Fallback just in case the loop finishes without calling the Notion tool or hitting the limit
    if analyzed_packets:
        print("\nFinished analyzing all packets. Creating Notion Document.")
        create_notion_page(analyzed_packets)