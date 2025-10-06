# GREENWIRE Cryptographic Operations Module

This directory contains all modules and data related to cryptographic operations for EMV, NFC, and smart card security testing within the GREENWIRE framework.

## Purpose

The primary goal of this module is to provide a centralized and self-contained system for handling cryptographic requirements, particularly for offline data authentication methods used in EMV transactions. This aligns with GREENWIRE's static distribution model, where all necessary components are included within the directory tree.

## Components

- **`authentication.py`**: Implements the logic for different offline authentication schemes.
  - `perform_sda()`: Placeholder for Static Data Authentication.
  - `perform_dda()`: Placeholder for Dynamic Data Authentication.
  - `perform_cda()`: Placeholder for Combined Data Authentication.

- **`keys.py`**: Handles the loading and management of public keys.
  - `get_ca_keys()`: Loads all Certification Authority (CA) public keys from `ca_keys.json`.
  - `find_ca_key()`: Retrieves a specific CA key based on its RID (Registered Application Provider Identifier) and index.

- **`ca_keys.json`**: A data file containing a list of known CA public keys used to verify card issuer signatures. Each key includes the RID, index, modulus, and exponent.

## Usage

Modules outside of this package can import these functions to perform cryptographic verification during EMV transaction analysis.

Example:

```python
from crypto.authentication import perform_sda

# ... obtain transaction data ...
is_authentic = perform_sda(rid, key_index, signed_data, static_data)
if is_authentic:
    print("SDA verification successful (placeholder).")
else:
    print("SDA verification failed (placeholder).")
```
