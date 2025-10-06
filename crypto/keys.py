# GREENWIRE Cryptographic Key Management
# Loads and provides access to CA public keys for EMV offline authentication.

import json
import os
from typing import List, Dict, Optional

_keys = None

def get_ca_keys() -> List[Dict[str, str]]:
    """Loads the CA public keys from the JSON file."""
    global _keys
    if _keys is None:
        keys_path = os.path.join(os.path.dirname(__file__), 'ca_keys.json')
        try:
            with open(keys_path, 'r') as f:
                _keys = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            # In a real scenario, log this error
            print(f"Error loading CA keys: {e}")
            _keys = []
    return _keys

def find_ca_key(rid: str, index: str) -> Optional[Dict[str, str]]:
    """
    Finds a specific CA public key by RID and key index.

    :param rid: The Registered Application Provider Identifier (RID).
    :param index: The Certification Authority Public Key Index.
    :return: The key dictionary if found, otherwise None.
    """
    keys = get_ca_keys()
    for key in keys:
        if key.get('rid') == rid and key.get('index') == index:
            return key
    return None

if __name__ == '__main__':
    # Example usage and verification
    all_keys = get_ca_keys()
    print(f"Loaded {len(all_keys)} CA public keys.")

    # Test finding a key
    visa_rid = "A000000003"
    visa_key_index = "92"
    visa_key = find_ca_key(visa_rid, visa_key_index)

    if visa_key:
        print(f"Found Visa key (Index {visa_key_index}):")
        print(f"  RID: {visa_key['rid']}")
        print(f"  Modulus: {visa_key['modulus'][:20]}...")
        print(f"  Exponent: {visa_key['exponent']}")
    else:
        print(f"Could not find Visa key with index {visa_key_index}.")

    # Test finding a non-existent key
    non_existent_key = find_ca_key("A000000000", "01")
    if not non_existent_key:
        print("Successfully verified that a non-existent key is not found.")

