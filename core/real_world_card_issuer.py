"""Compatibility shim for legacy import path.

Provides `from core.real_world_card_issuer import RealWorldCardIssuer` while
the canonical implementation now lives under the namespaced package:
`greenwire.core.real_world_card_issuer`.
"""
from greenwire.core.real_world_card_issuer import *  # type: ignore F401,F403
