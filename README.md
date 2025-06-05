# Operation Greenwire — SMS Tools Modules

**Mission:** Empower ethical, open research into GSM SMS, TLV, WAP Push, and STK smartcard technologies.

**License:** GPL v3
**Dedication:** To O-B-I-E Patrick Moore, 101st Airborne, trained Green Beret (1967, Dac To, Silver Star recipient), and all who stand for freedom.

---

## Modules

- **lib/PDU.pm** — Build GSM SMS PDUs from number and message.
- **lib/Multipart.pm** — Split long SMS into multipart concatenated PDUs.
- **lib/WAP.pm** — Build simple binary WAP push/provisioning messages.
- **lib/STK.pm** — Build simple sample SIM Toolkit command payloads.
- **lib/TLV.pm** — Parse TLV-formatted (Tag-Length-Value) hex streams for SIM/OTA/EMV.

---

## Usage Example

```perl
use lib './lib';
use PDU qw(build);
my $pdu = build('+1234567890', 'Hello World!');
print "$pdu\n";
