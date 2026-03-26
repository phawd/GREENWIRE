from dataclasses import dataclass
from typing import List, Optional

@dataclass
class GPAttackScenario:
    id: str           # GP-001 format
    name: str
    target: str       # ISD / SSD / APP / CARD
    scp_version: str  # SCP02 / SCP03 / BOTH
    attack_apdus: List[str]  # hex APDU sequence
    expected_responses: List[str]
    description: str
    vuln_id: Optional[str]  # links to vulnerability_registry
    requires_keys: bool
    key_type: Optional[str]  # DEFAULT / DERIVED / CUSTOM

_scenarios = [
    GPAttackScenario(
        id="GP-001",
        name="Open ISD with default JCOP lab key (SCP02)",
        target="ISD",
        scp_version="SCP02",
        attack_apdus=["8050000008...", "80FA..."],
        expected_responses=["9000", "6985"],
        description="Authenticate to ISD using default JCOP lab keys (404142...4F) via SCP02.",
        vuln_id="GW-2024-0007",
        requires_keys=True,
        key_type="DEFAULT"
    ),
    GPAttackScenario(
        id="GP-002",
        name="Open ISD with default JCOP lab key (SCP03)",
        target="ISD",
        scp_version="SCP03",
        attack_apdus=["8050000008...", "80FA..."],
        expected_responses=["9000", "6985"],
        description="Authenticate to ISD using default JCOP lab keys via SCP03.",
        vuln_id="GW-2024-0016",
        requires_keys=True,
        key_type="DEFAULT"
    ),
    GPAttackScenario(
        id="GP-003",
        name="LIST ALL applications",
        target="CARD",
        scp_version="BOTH",
        attack_apdus=["80F21000024F00"],
        expected_responses=["6F...9000"],
        description="List all packages, applets, and security domains on the card.",
        vuln_id=None,
        requires_keys=False,
        key_type=None
    ),
    GPAttackScenario(
        id="GP-004",
        name="GET CARD DATA",
        target="CARD",
        scp_version="BOTH",
        attack_apdus=["80CA006600"],
        expected_responses=["66...9000"],
        description="Get card production life cycle and OP system info.",
        vuln_id="GW-2024-0020",
        requires_keys=False,
        key_type=None
    ),
    GPAttackScenario(
        id="GP-005",
        name="INSTALL [for load] + LOAD CAP file segments",
        target="ISD",
        scp_version="BOTH",
        attack_apdus=["80E6020014...", "80E80000..."],
        expected_responses=["9000"],
        description="Install for load and load CAP file segments.",
        vuln_id=None,
        requires_keys=True,
        key_type="DERIVED"
    ),
    GPAttackScenario(
        id="GP-006",
        name="INSTALL [for install + make selectable]",
        target="ISD",
        scp_version="BOTH",
        attack_apdus=["80E6020014...", "80E80000..."],
        expected_responses=["9000"],
        description="Install for install and make applet selectable.",
        vuln_id=None,
        requires_keys=True,
        key_type="DERIVED"
    ),
    GPAttackScenario(
        id="GP-007",
        name="DELETE applet (by AID)",
        target="ISD",
        scp_version="BOTH",
        attack_apdus=["80E4000010..."],
        expected_responses=["9000"],
        description="Delete applet by AID.",
        vuln_id=None,
        requires_keys=True,
        key_type="DERIVED"
    ),
    GPAttackScenario(
        id="GP-008",
        name="DELETE package (by AID)",
        target="ISD",
        scp_version="BOTH",
        attack_apdus=["80E4000010..."],
        expected_responses=["9000"],
        description="Delete package by AID.",
        vuln_id=None,
        requires_keys=True,
        key_type="DERIVED"
    ),
    GPAttackScenario(
        id="GP-009",
        name="STORE DATA to Supplementary Security Domain",
        target="SSD",
        scp_version="BOTH",
        attack_apdus=["80E2000010..."],
        expected_responses=["9000"],
        description="Store data to SSD.",
        vuln_id=None,
        requires_keys=True,
        key_type="DERIVED"
    ),
    GPAttackScenario(
        id="GP-010",
        name="PUT KEY — replace ISD key set",
        target="ISD",
        scp_version="BOTH",
        attack_apdus=["80D8000010..."],
        expected_responses=["9000"],
        description="Replace ISD key set using PUT KEY.",
        vuln_id="GW-2024-0008",
        requires_keys=True,
        key_type="DERIVED"
    ),
    GPAttackScenario(
        id="GP-011",
        name="GET STATUS of Security Domain",
        target="SSD",
        scp_version="BOTH",
        attack_apdus=["80F2000002..."],
        expected_responses=["9000"],
        description="Get status of SSD.",
        vuln_id=None,
        requires_keys=True,
        key_type="DERIVED"
    ),
    GPAttackScenario(
        id="GP-012",
        name="MANAGE CHANNEL — open/close logical channels",
        target="CARD",
        scp_version="BOTH",
        attack_apdus=["0070000001...", "0070800001..."],
        expected_responses=["9000"],
        description="Open and close logical channels.",
        vuln_id="GW-2024-0006",
        requires_keys=False,
        key_type=None
    ),
    GPAttackScenario(
        id="GP-013",
        name="GET DATA — card recognizer data (tag 66h)",
        target="CARD",
        scp_version="BOTH",
        attack_apdus=["80CA006600"],
        expected_responses=["66...9000"],
        description="Get card recognizer data (tag 66h).",
        vuln_id="GW-2024-0001",
        requires_keys=False,
        key_type=None
    ),
    GPAttackScenario(
        id="GP-014",
        name="SET STATUS — lock/unlock application",
        target="APP",
        scp_version="BOTH",
        attack_apdus=["80F0000010..."],
        expected_responses=["9000"],
        description="Lock or unlock application using SET STATUS.",
        vuln_id=None,
        requires_keys=True,
        key_type="DERIVED"
    ),
    GPAttackScenario(
        id="GP-015",
        name="EXTRADITE application to different SSD",
        target="APP",
        scp_version="BOTH",
        attack_apdus=["80E6000010..."],
        expected_responses=["9000"],
        description="Move application to a different SSD.",
        vuln_id=None,
        requires_keys=True,
        key_type="DERIVED"
    ),
]

def list_scenarios() -> List[GPAttackScenario]:
    return _scenarios

def get_scenario(scenario_id: str) -> Optional[GPAttackScenario]:
    for s in _scenarios:
        if s.id == scenario_id:
            return s
    return None
