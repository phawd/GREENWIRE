from greenwire.core.hsm_emulator import HSMEmulator


def test_generate_e_applet():
    hsm = HSMEmulator(issuer="BankX")
    applet = hsm.generate_e_applet()
    assert applet.card["issuer"] == "BankX"
    assert "pan" in applet.card
    assert isinstance(applet.public_modulus, str)
    assert isinstance(applet.signature, bytes)
