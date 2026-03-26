import binascii
from datetime import datetime, timezone
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend

class HCEEmulator:
    """
    Host Card Emulation: software card running on Android phone via NFC.
    Simulates the card-side of an EMV contactless transaction using
    Limited Use Keys (LUKs) pre-provisioned by the TSP (Token Service Provider).
    Reference: Visa VTS HCE Spec v2.0, MC MDES Cloud-Based Payments Spec v3.1
    """
    AID_MAP = {
        'visa': b'A0000000031010',
        'mc': b'A0000000041010',
        'amex': b'A000000025010402',
    }
    SERVICE_CODE = b'101'
    CARDHOLDER_NAME = b'GREENWIRE/TEST'

    def __init__(self, pan, expiry_mmyy, scheme='visa', atc_start=0, luk_pool=None):
        self.pan = pan
        self.expiry = expiry_mmyy
        self.scheme = scheme.lower()
        self.atc = atc_start
        self.luk_pool = luk_pool or []
        self.luk_index = 0
        self.transaction_log = []
        self.aid = self.AID_MAP.get(self.scheme, self.AID_MAP['visa'])

    def provision_luk_pool(self, luk_list):
        self.luk_pool = luk_list
        self.luk_index = 0

    def process_apdu(self, apdu_hex):
        apdu = binascii.unhexlify(apdu_hex)
        cla, ins, p1, p2, *rest = apdu[:4], apdu[4:5], apdu[5:6], apdu[6:7], apdu[7:]
        ins = apdu[1]
        if ins == 0xA4:  # SELECT
            resp = self._handle_select(apdu)
        elif ins == 0x82:  # GPO
            resp = self._handle_gpo(apdu)
        elif ins == 0xB2:  # READ RECORD
            resp = self._handle_read_record(apdu)
        elif ins == 0xAE:  # GENERATE AC
            resp = self._handle_generate_ac(apdu)
        else:
            return '6A82'  # File not found
        return binascii.hexlify(resp).upper().decode()

    def _handle_select(self, apdu):
        # SELECT by AID
        aid = self.aid
        # Check if AID matches
        if aid not in apdu:
            return b'6A82'
        # FCI Template: 6F...
        fci = b'6F' + self._tlv(b'84', aid) + self._tlv(b'A5', b'')
        return fci + b'9000'

    def _handle_gpo(self, apdu):
        # GPO returns AIP + AFL
        aip = self._build_aip()
        afl = self._build_afl()
        resp = self._tlv(b'80', aip + afl)
        return resp + b'9000'

    def _handle_read_record(self, apdu):
        # SFI in P2 upper 5 bits, record in P1
        p1 = apdu[2]
        p2 = apdu[3]
        sfi = (p2 >> 3) & 0x1F
        record = p1
        if sfi == 1 and record == 1:
            data = self._build_record_1_1()
        elif sfi == 2 and record == 1:
            data = self._build_record_2_1()
        else:
            return b'6A82'
        return data + b'9000'

    def _handle_generate_ac(self, apdu):
        # GENERATE AC: CDOL1 data in apdu[5:]
        cdol_data = apdu[5:]
        arqc = self._compute_arqc(cdol_data)
        atc_bytes = self.atc.to_bytes(2, 'big')
        resp = self._tlv(b'77',
            self._tlv(b'9F27', b'80') +
            self._tlv(b'9F36', atc_bytes) +
            self._tlv(b'9F26', arqc) +
            self._tlv(b'9F10', b'0000000000')
        )
        # Log transaction
        self.transaction_log.append({
            'datetime': datetime.now(timezone.utc).isoformat(),
            'atc': self.atc,
            'arqc': binascii.hexlify(arqc).decode(),
            'cdol_data': binascii.hexlify(cdol_data).decode(),
        })
        self.atc += 1
        self.luk_index += 1
        return resp + b'9000'

    def _compute_arqc(self, cdol_data):
        # Use next LUK as 16-byte key (3DES)
        if self.luk_index >= len(self.luk_pool):
            key = b'\x00' * 16
        else:
            key = self.luk_pool[self.luk_index]
        # 3DES MAC (ECB, single block)
        cipher = Cipher(TripleDES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        # Pad cdol_data to 8 bytes
        padded = cdol_data + b'\x00' * (8 - len(cdol_data) % 8)
        mac = encryptor.update(padded[:8])[:8]
        return mac

    def _build_aip(self):
        return b'\x58\x00'

    def _build_afl(self):
        # SFI 1: rec 1-2, SFI 2: rec 1
        return b'\x10\x01\x02\x00' + b'\x20\x01\x01\x00'

    def _build_record_1_1(self):
        # PAN, expiry, service code, Track2
        pan_b = self._bcd(self.pan)
        expiry_b = self._bcd(self.expiry)
        track2 = self.pan + 'D' + self.expiry + self.SERVICE_CODE.decode() + '000000000000'
        track2_b = self._bcd(track2)
        tlvs = (
            self._tlv(b'5A', pan_b) +
            self._tlv(b'5F24', expiry_b) +
            self._tlv(b'5F20', self.CARDHOLDER_NAME) +
            self._tlv(b'57', track2_b)
        )
        return tlvs

    def _build_record_2_1(self):
        # CDOL1, CDOL2, CVM list (dummy)
        return self._tlv(b'8C', b'9F02065F2A029A039C0195059F3704') + self._tlv(b'8D', b'')

    def get_transaction_log(self):
        return self.transaction_log

    def reset(self):
        self.atc = 0
        self.luk_index = 0
        self.transaction_log = []

    @staticmethod
    def _tlv(tag, value):
        if isinstance(tag, str):
            tag = binascii.unhexlify(tag)
        if isinstance(value, str):
            value = binascii.unhexlify(value)
        length = len(value)
        if length < 0x80:
            len_bytes = bytes([length])
        else:
            len_bytes = bytes([0x81, length])
        return tag + len_bytes + value

    @staticmethod
    def _bcd(s):
        # Convert string to BCD bytes
        s = s.replace('D', 'd')
        if len(s) % 2:
            s += 'F'
        return binascii.unhexlify(s.replace('d', 'D'))
