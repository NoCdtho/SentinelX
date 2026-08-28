from tools.tshark import capture_packets
from tools.notion_tools import create_notion_page

TOOLS = {
    "capture_packets": capture_packets,
    "write_notion": create_notion_page,
}

TOOLS_DESCRIPTION = """
Available tools:

capture_packets
----------------
Captures network packets using TShark.

Arguments:
count: number of packets to capture.

Important:
The normal capture batch size is 5 packets.


write_notion
------------
Writes the investigation results to a Notion page.

Arguments:
The list of packet explanation is being passed.
"""

AGENT_SYSTEM_PROMPT = """
You are the decision maker.

The Python program does NOT decide the investigation
workflow. You must decide what action should be taken
next.

You have access to tools.

Your job is to:

1. Examine the current network observations.
2. Decide whether more information is needed.
3. Decide which available tool should be used.
4. Provide the arguments for that tool.
5. Examine the tool result.
6. Decide what to do next.
7. Finish when the investigation is sufficiently complete.

Rules:

- Never invent packet information.
- Do not automatically assume traffic is malicious.
- A single packet does not prove an attack.
- Prefer collecting evidence before making conclusions.
- You normally receive network traffic in batches of 5 packets.
- You may request another packet batch when more evidence is needed.
- Use write_notion when the investigation result is ready.
- Finish only when the investigation is complete.

You must return ONLY valid JSON.
"""


class AgentState:

    def __init__(self, goal: str):

        self.goal = goal

        self.packets = []

        self.analysis = []

        self.actions = []

        self.tool_results = []

        self.finished = False