import sys
import time
from config import MAX_PACKETS, TSHARK_INTERFACE, validate_configuration, MAX_PACKETS_LIMIT
from tools.tshark import check_tshark, capture_packets
from parser import parse_packet
from analyzer import analyze_packet_with_local_llm
from tools.notion_tools import create_notion_page

def analysis():

    # This functions ensures all the required variables are set.
    is_validate: bool = validate_configuration()
    if not is_validate:
        print("there is something missing in config check it")
        sys.exit(1)

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
        print(packet)
        parsed_packets.append(packet)
        print(f"[{index}/{len(packets_raw)}]")

    # LLM Security Analysis
    print("\nLLM SECURITY ANALYSIS\n")

    # I want to store the explanation of captured packets so far 
    analyzed_packets = []

    # Iterate directly through the parsed packets list. 
    # Python allows dynamically appending to a list while iterating over it.
    for packet in parsed_packets:

        if len(parsed_packets) > 5:
            print("limit reached look 5 packet are explained")
            break

        decision_and_explanation = analyze_packet_with_local_llm(packet)
        packet_data_for_notion = {
            "packet": packet,
            "analysis": decision_and_explanation
        }

        print()
        tool = decision_and_explanation.get("tool_name")
        print(f"\nAgent wants to call the tool: {tool} ")

        explanation = decision_and_explanation.get("explanation")
        print("\nExplanation from the LLM is: ", explanation)

        # append the packet and analyzed in the list
        analyzed_packets.append(packet_data_for_notion)
        
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

            print("\nCREATING NOTION DOCUMENT\n")
            create_notion_page(analyzed_packets)
            
            return

    # Fallback just in case the loop finishes without calling the Notion tool or hitting the limit
    if analyzed_packets:
        print("\nFinished analyzing all packets. Creating Notion Document.")
        create_notion_page(analyzed_packets)
        return
