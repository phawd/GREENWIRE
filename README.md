# Operation Greenwire — Swiss army knife of ISO7xxx Tools Modules

**Mission:** Empower ethical, open research into GSM SMS, TLV, WAP Push, and STK smartcard technologies.

**License:** GPL v3
**Dedication:** To MOORE, 101st Airborne, trained Green Beret (1967, Dac To, Silver Star recipient), and all who stand for freedom.

---

---

### Python Unified CLI: greenwire.py

`greenwire.py` is a unified command-line tool for both EMV card issuing and SMS PDU building. It wraps the Python EMV issuer and the Perl SMS CLI.

#### Requirements

- Python 3.x
- Perl (for SMS CLI)
- OpenSSL (for EMV PKI)
- Google Drive API dependencies (for upload):
  - `google-api-python-client`
  - `google-auth-httplib2`
  - `google-auth-oauthlib`
- `service-account.json` (for Google Drive upload, if used)

#### Usage

**Issue EMV Cards:**

```
python3 greenwire.py emv --scheme visa --count 3 --upload
```
- `--scheme` can be `visa`, `mc`, or `amex`
- `--count` is the number of cards to issue
- `--upload` uploads all PEM/DER/ZIP outputs to Google Drive

**Build/Send SMS (Perl backend):**

```
python3 greenwire.py sms --mode pdu --number +1234567890 --message "Hello World!"
```
Other SMS CLI modes are supported (see below).

**Show Perl SMS CLI Help:**

```
python3 greenwire.py --help-sms
```

#### Perl SMS CLI Modes (examples)

```
./greenwire-cli.pl --mode pdu --number +1234567890 --message "Hello"
./greenwire-cli.pl --mode tlv --tlv "84080123456789ABCD8502EF01"
```

#### Notes
- Place your Perl modules and `greenwire-cli.pl` in the same directory or adjust the path.
- For Google Drive upload, ensure `service-account.json` is present.
- All EMV and SMS logic is unified in `greenwire.py` for convenience.
