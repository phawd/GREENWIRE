def toHexString(data):
    return ' '.join(f'{b:02X}' for b in data)

def toBytes(s):
    return bytes.fromhex(s.replace(' ', ''))
