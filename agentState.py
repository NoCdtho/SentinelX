from dataclasses import dataclass, field # this import functions that are mainly used to store data with less boilerplate code
from typing import List, Dict, Any # used to tell the type of variable is. 
from enum import Enum

class AgentStatus(Enum): # This is a custom enumeration  
 INIT = "INIT" # agent has started working 
 STARTED = "STARTED" # LLM is processing 
 TOOL_EXECUTION = "TOOL_EXECUTION" # Tool executed completed 
 TOOL_FAILED = "TOOL_FAILED" # Tool failed to execute 
 COMPLETED = "COMPLETED" # task is completed by the agent

@dataclass
class AgentState:
    # 1. store the LLM decision and result from a tool 
    messages: List[Dict[str, Any]] = field(default_factory=list) # Dictionary the keys should be string and values can be any type and default value that is assinged makes a new list is created everytime the new instance of the class is created.
    
    # 2. Number of packets examined
    packets_examined: int = 0
    
    # 3. Tracks the current status of the agent
    status: AgentStatus = AgentStatus.STARTED
    
    # 4. Stores the tool call made by the LLM
    current_tool_call: Dict[str, Any] = field(default_factory=dict)


    def add_message(self, role: str, content: str, name: str):
        """Helper to format messages for Qwen."""
        msg = {"role": role, "content": content}
        if name:
            msg["name"] = name  # Useful for identifying tool responses
        self.messages.append(msg)