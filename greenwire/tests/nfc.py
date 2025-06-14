"""Minimal NFC mock for unit tests."""


class ContactlessFrontend:
    """Stubbed interface mimicking nfcpy's ContactlessFrontend."""

    def __init__(self, *args, **kwargs):
        pass

    def close(self):
        pass
