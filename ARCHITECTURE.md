# GREENWIRE Architecture (Legacy Overview)

> **Status:** Historical reference. See `docs/ARCHITECTURE_V5_MULTITHREADED.md` for the current design.

```text
├── modules.crypto.* (Cryptographic functions)
└── core.fuzzing_engine (Testing capabilities)

modules.crypto.*
├── core.utils.crypto_utils (Basic crypto functions)
## Legacy Summary

This file serves as an archive snapshot of the pre-v5 architecture for historical reference. The structure diagram above reflects how core and module packages were organised before the multithreaded issuer pipeline was introduced.

## Migration Guidance

- Prefer the workflows and service descriptions documented in `docs/ARCHITECTURE_V5_MULTITHREADED.md`.
- Retain this file only to interpret older research notes, scripts, or automation that depended on the legacy layout.
- Remove or archive unused legacy components once the v5 pipeline reaches feature parity.
3. New attack vectors can be added without core changes
4. Research integration allows rapid implementation of new techniques

## Future Extensions

### Planned Enhancements

- **Machine Learning Integration**: Automated attack pattern recognition
- **Cloud Research**: Distributed key recovery across multiple instances
- **Hardware Extensions**: Support for specialized attack hardware
- **Mobile Integration**: Android NFC attack capabilities

This architecture supports both security research and practical penetration testing while maintaining clear organization and extensibility for future cryptographic attack development.
