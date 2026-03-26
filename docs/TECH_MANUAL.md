# GREENWIRE — Technician Quick-Start Manual

**Version:** 2025 | **Audience:** Lab Technician (no prior EMV knowledge required)

---

## 1. What is GREENWIRE?

GREENWIRE is a payment-card lab tool that lets you read, write, and test smart cards and NFC devices. It works with physical chip cards (contact and contactless), Android phones acting as virtual cards, and simulated bank/POS/ATM systems. Use it in the lab — never on real customer cards.

---

## 2. Lab Setup

**You will need:**
- A Windows or Linux PC with Python 3.10+
- A USB smart-card reader (ACR122U, ACR1252U, or Identiv SCR3310)
- Optionally: an Android phone with NFC, USB cable, USB debugging enabled

**Install once:**
```
pip install -r requirements.txt
```
No internet is required after the first install.

---

## 3. First Run

Open a terminal in `F:\repo\GREENWIRE`, then:

```
python greenwire.py --menu
```

The interactive menu appears. Use the **arrow keys** or **number keys** to navigate. Press **Q** to quit.

To run a single command without the menu:
```
python greenwire.py apdu --list-readers
```

---

## 4. Connecting an Android Device

1. On the phone: **Settings → Developer Options → enable USB Debugging** (toggle on).
2. Plug in the USB cable. Accept the "Allow USB debugging?" prompt on the phone.
3. In the terminal, run:
   ```
   python greenwire.py android-bridge --connect
   ```
4. Confirm the device appears:
   ```
   python greenwire.py android-bridge --status
   ```
5. You should see `Device: CONNECTED`. The phone is now a virtual NFC card reader/emulator.

---

## 5. Running a Test Tap

1. Start the menu: `python greenwire.py --menu`
2. Select **NFC / Card Testing → Test Tap**.
3. When prompted, tap the card (or phone) to the reader.
4. GREENWIRE sends a SELECT command and reads the card response.
5. The result prints to the screen and saves to the `artifacts/` folder.

**Quick CLI version:**
```
python greenwire.py apdu --command 00A4040007A0000000031010 --verbose
```

---

## 6. Reading the Output

| Term | Meaning |
|------|---------|
| **PASS** | The card responded correctly; all checks passed |
| **FAIL** | The card returned an unexpected response or error code |
| **ARQC** | Authorisation Request Cryptogram — a 8-byte proof the card generated for a transaction |
| **SW 9000** | Status Word 9000 = "OK" from the card |
| **SW 6A82** | File/application not found |
| **SW 6300** | Transaction failed (wrong PIN, limit exceeded) |

Artifact files in `artifacts/` are JSON; open them in any text editor.

---

## 7. Common Problems & Fixes

| Problem | Fix |
|---------|-----|
| `No readers found` | Unplug and re-plug the USB reader. Restart the PC/SC service: `net stop SCardSvr && net start SCardSvr` |
| `Android device not detected` | Re-enable USB Debugging and accept the prompt on the phone again |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` again |
| `6A82 — app not found` | The card does not have the EMV application. Try a different AID or a different card |
| `ARQC mismatch` | The card key in `global_defaults.json` does not match the card. Check key slot settings in the menu |

---

## 8. Who To Call

| Situation | Contact |
|-----------|---------|
| Reader not working after reboot | **Lab Lead** — check USB/driver |
| Unexpected SW codes not in this manual | **EMV Engineer** — bring the artifact JSON |
| Cryptographic errors / key mismatch | **Security Engineer** — do not attempt to fix keys yourself |
| Spec questions | EMV Book 1–4 (in `docs/`) or [https://www.emvco.com](https://www.emvco.com) |

---

*Keep this page at the workstation. For deeper technical detail see `docs/ENGINEERING_MANUAL.md`.*
