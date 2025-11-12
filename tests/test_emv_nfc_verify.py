"""Tests for EMV NFC verification helpers."""

from emv_nfc_verify import EMVNFCVerifier


class DummyCommunicator:
    """Simple stand-in APDU communicator for unit tests."""

    def __init__(self):
        self.commands = []

    def send_apdu(self, command: str):
        self.commands.append(command)
        if command.startswith("00A40400"):
            return "6F00", "9000"
        if command == "80A80000028300":
            return "7700", "9000"
        return "", "6A82"


def test_single_aid_command_building_and_gpo_execution():
    """_test_single_aid should build proper SELECT APDU and run GPO."""

    verifier = EMVNFCVerifier()
    dummy_comm = DummyCommunicator()

    aid = "A0000000031010"  # Visa classic test AID
    result = verifier._test_single_aid(dummy_comm, aid)  # pylint: disable=protected-access

    assert dummy_comm.commands[0] == "00A4040007A0000000031010"
    assert dummy_comm.commands[1] == "80A80000028300"
    assert result["select_success"] is True
    assert result["gpo_test"]["gpo_success"] is True
