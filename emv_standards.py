"""EMV Standards and Card Scheme definitions for GREENWIRE."""

from enum import Enum
import binascii

class CardScheme(Enum):
    """EMV card schemes."""
    VISA = "visa"
    MASTERCARD = "mastercard"
    AMEX = "amex"
    DISCOVER = "discover"
    JCB = "jcb"
    UNIONPAY = "unionpay"

# EMV standards data
emv_standards = {
    "visa": {
        "aid_prefixes": ["A0000000031010", "A000000003101001", "A0000000032010", "A0000000032020"],
        "card_number_length": [13, 16, 19],
        "cvv_length": 3,
        "expiry_format": "MMYY",
        "bin_ranges": ["4"],
        "test_cards": ["4000000000000002", "4111111111111111", "4242424242424242"]
    },
    "mastercard": {
        "aid_prefixes": ["A0000000041010", "A000000004101001", "A0000000042203"],
        "card_number_length": [16],
        "cvv_length": 3,
        "expiry_format": "MMYY",
        "bin_ranges": ["5", "2"],
        "test_cards": ["5555555555554444", "5105105105105100", "2223003122003222"]
    },
    "amex": {
        "aid_prefixes": ["A000000025010401", "A000000025010701", "A00000002501"],
        "card_number_length": [15],
        "cvv_length": 4,
        "expiry_format": "MMYY",
        "bin_ranges": ["34", "37"],
        "test_cards": ["378282246310005", "371449635398431", "378734493671000"]
    },
    "discover": {
        "aid_prefixes": ["A0000001523010", "A0000001524010"],
        "card_number_length": [16],
        "cvv_length": 3,
        "expiry_format": "MMYY",
        "bin_ranges": ["6011", "644", "645", "646", "647", "648", "649", "65"],
        "test_cards": ["6011111111111117", "6011000990139424"]
    }
}

# EMV Application Protocol Data Unit commands
EMV_COMMANDS = {
    "SELECT": "00A40400",
    "GET_PROCESSING_OPTIONS": "80A80000",
    "READ_RECORD": "00B2",
    "GET_DATA": "80CA",
    "VERIFY": "0020",
    "GENERATE_AC": "80AE",
    "GET_CHALLENGE": "0084",
    "EXTERNAL_AUTHENTICATE": "0082",
    "INTERNAL_AUTHENTICATE": "0088"
}

# EMV Tags
EMV_TAGS = {
    "4F": "Application Identifier (AID)",
    "50": "Application Label", 
    "57": "Track 2 Equivalent Data",
    "5A": "Application Primary Account Number (PAN)",
    "5F20": "Cardholder Name",
    "5F24": "Application Expiration Date",
    "5F25": "Application Effective Date",
    "5F28": "Issuer Country Code",
    "5F2A": "Transaction Currency Code",
    "5F34": "Application Primary Account Number (PAN) Sequence Number",
    "82": "Application Interchange Profile",
    "84": "Dedicated File (DF) Name",
    "87": "Application Priority Indicator",
    "88": "Short File Identifier (SFI)",
    "8A": "Authorization Response Code",
    "8C": "Card Risk Management Data Object List 1 (CDOL1)",
    "8D": "Card Risk Management Data Object List 2 (CDOL2)",
    "8E": "Cardholder Verification Method (CVM) List",
    "8F": "Certification Authority Public Key Index",
    "90": "Issuer Public Key Certificate",
    "92": "Issuer Public Key Remainder",
    "93": "Signed Static Application Data",
    "94": "Application File Locator (AFL)",
    "95": "Terminal Verification Results",
    "9A": "Transaction Date",
    "9C": "Transaction Type",
    "9F02": "Amount, Authorized (Numeric)",
    "9F03": "Amount, Other (Numeric)",
    "9F06": "Application Identifier (AID) - terminal",
    "9F07": "Application Usage Control",
    "9F08": "Application Version Number",
    "9F09": "Application Version Number",
    "9F0D": "Issuer Action Code - Default",
    "9F0E": "Issuer Action Code - Denial",
    "9F0F": "Issuer Action Code - Online",
    "9F10": "Issuer Application Data",
    "9F26": "Application Cryptogram",
    "9F27": "Cryptogram Information Data",
    "9F36": "Application Transaction Counter (ATC)",
    "9F37": "Unpredictable Number",
    "9F38": "Processing Options Data Object List (PDOL)",
    "9F42": "Application Currency Code",
    "9F44": "Application Currency Exponent"
}

def parse_tlv(data):
    """Parse TLV (Tag-Length-Value) data structure."""
    tlv_data = {}
    i = 0
    data_bytes = binascii.unhexlify(data) if isinstance(data, str) else data
    
    while i < len(data_bytes):
        # Parse tag
        tag = data_bytes[i]
        i += 1
        
        if tag & 0x1F == 0x1F:  # Multi-byte tag
            tag_bytes = [tag]
            while i < len(data_bytes) and data_bytes[i] & 0x80:
                tag_bytes.append(data_bytes[i])
                i += 1
            if i < len(data_bytes):
                tag_bytes.append(data_bytes[i])
                i += 1
            tag_str = ''.join(f'{b:02X}' for b in tag_bytes)
        else:
            tag_str = f'{tag:02X}'
        
        if i >= len(data_bytes):
            break
            
        # Parse length
        length = data_bytes[i]
        i += 1
        
        if length & 0x80:  # Multi-byte length
            length_bytes = length & 0x7F
            if length_bytes > 0 and i + length_bytes <= len(data_bytes):
                length = 0
                for j in range(length_bytes):
                    length = (length << 8) | data_bytes[i]
                    i += 1
        
        # Parse value
        if i + length <= len(data_bytes):
            value = data_bytes[i:i+length]
            tlv_data[tag_str] = {
                'description': EMV_TAGS.get(tag_str, f'Unknown tag {tag_str}'),
                'value': value.hex().upper(),
                'raw_value': value
            }
            i += length
        else:
            break
    
    return tlv_data

def luhn_checksum(card_num):
    """Calculate Luhn checksum for card number validation."""
    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(card_num)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d*2))
    return checksum % 10

def is_valid_card_number(card_num):
    """Validate card number using Luhn algorithm."""
    return luhn_checksum(card_num) == 0

def get_card_scheme(card_num):
    """Identify card scheme from card number."""
    card_str = str(card_num)
    
    if card_str.startswith('4'):
        return CardScheme.VISA
    elif card_str.startswith(('51', '52', '53', '54', '55', '2221', '2222', '2223', '2224', '2225', '2226', '2227', '2228', '2229', '223', '224', '225', '226', '227', '228', '229', '23', '24', '25', '26', '270', '271', '2720')):
        return CardScheme.MASTERCARD
    elif card_str.startswith(('34', '37')):
        return CardScheme.AMEX
    elif card_str.startswith(('6011', '644', '645', '646', '647', '648', '649', '65')):
        return CardScheme.DISCOVER
    elif card_str.startswith(('35', '2131', '1800')):
        return CardScheme.JCB
    elif card_str.startswith('62'):
        return CardScheme.UNIONPAY
    else:
        return None

def generate_luhn_valid_card(prefix, length):
    """Generate a Luhn-valid card number with given prefix and length."""
    import random
    
    # Generate random digits for the card number (except last digit)
    card_digits = list(str(prefix).ljust(length-1, '0')[:length-1])
    for i in range(len(str(prefix)), length-1):
        card_digits[i] = str(random.randint(0, 9))
    
    # Calculate Luhn checksum digit
    total = 0
    for i, digit in enumerate(card_digits[::-1]):  # Reverse for calculation
        n = int(digit)
        if i % 2 == 1:  # Every second digit from right
            n *= 2
            if n > 9:
                n = n // 10 + n % 10
        total += n
    
    checksum_digit = (10 - (total % 10)) % 10
    card_digits.append(str(checksum_digit))
    
    return ''.join(card_digits)

def generate_compliant_card_data(scheme, card_type="credit"):
    """Generate EMV-compliant card data for a given scheme."""
    import random
    import datetime
    
    scheme_data = emv_standards[scheme.value]
    
    # Generate valid card number
    if scheme == CardScheme.VISA:
        prefix = "4"
        length = random.choice([16, 19])
    elif scheme == CardScheme.MASTERCARD:
        prefix = random.choice(["51", "52", "53", "54", "55"])
        length = 16
    elif scheme == CardScheme.AMEX:
        prefix = random.choice(["34", "37"])
        length = 15
    else:
        prefix = "4"  # Default to Visa
        length = 16
    
    pan = generate_luhn_valid_card(prefix, length)
    
    # Generate expiry date (1-3 years from now)
    now = datetime.datetime.now()
    expiry_months = random.randint(12, 36)
    expiry_date = now + datetime.timedelta(days=expiry_months * 30)
    expiry = expiry_date.strftime("%m%y")
    
    # Generate service code based on card type
    service_codes = {
        "credit": "201",   # International, normal authorization, PIN verification
        "debit": "221",    # International, normal authorization, PIN verification
        "prepaid": "101"   # International, normal authorization, no restrictions
    }
    service_code = service_codes.get(card_type, "201")
    
    # Generate CVV
    cvv_length = scheme_data["cvv_length"]
    cvv = ''.join([str(random.randint(0, 9)) for _ in range(cvv_length)])
    
    # Generate AID for the scheme
    aid = random.choice(scheme_data["aid_prefixes"])
    
    # Generate discretionary data
    discretionary_data = ''.join([str(random.randint(0, 9)) for _ in range(4)])
    
    return {
        "pan": pan,
        "expiry": expiry,
        "service_code": service_code,
        "cvv": cvv,
        "aid": aid,
        "scheme": scheme.value,
        "card_type": card_type,
        "discretionary_data": discretionary_data,
        "track1": f"%B{pan}^CARDHOLDER/TEST^{expiry}{service_code}{discretionary_data}?",
        "track2": f";{pan}={expiry}{service_code}{discretionary_data}?",
        "issuer_code": pan[0],
        "icc_data": {
            "9F06": aid,  # AID
            "5A": pan,    # PAN
            "5F24": expiry,  # Expiry
            "5F25": expiry[:2] + str(int(expiry[2:]) - 5),  # Effective date
            "9F08": "0001",  # App version
            "9F42": "0840",  # Currency code (USD)
            "8C": "9F02069F03069F1A0295055F2A029A039C0137",  # CDOL1
            "8D": "8A0230059F37045F2A02",  # CDOL2
            "8E": "000000000000000042031E031F00",  # CVM List
            "94": "18010A01"  # AFL
        },
        "terminal_capabilities": {
            "manual_key_entry": True,
            "magnetic_stripe": True,
            "ic_with_contacts": True,
            "ic_contactless": True
        },
        "cvm_requirements": [
            "signature",
            "offline_pin",
            "online_pin"
        ]
    }

def generate_multiple_easy_approval_cards(count, scheme):
    """Generate multiple cards optimized for easy approval."""
    cards = []
    
    for i in range(count):
        card_data = generate_compliant_card_data(scheme)
        
        # Modify for easy approval
        card_data.update({
            "pin": "1234",  # Simple PIN
            "description": f"Easy approval test card #{i+1}",
            "floor_limits": {
                "cvm_floor_limit": 2500,    # $25.00
                "no_cvm_floor_limit": 50,   # $0.50
                "contactless_limit": 10000  # $100.00
            },
            "approval_probability": 0.95,  # 95% approval rate
            "easy_approval_features": {
                "low_floor_limits": True,
                "simple_pin": True,
                "minimal_auth": True,
                "test_optimized": True
            }
        })
        
        cards.append(card_data)
    
    return cards

def get_scheme_spec(scheme):
    """Get scheme specifications."""
    class SchemeSpec:
        def __init__(self, scheme):
            self.scheme = scheme
    
    return SchemeSpec(scheme)