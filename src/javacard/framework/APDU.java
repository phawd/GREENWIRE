/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.APDU – the Application Protocol Data Unit.
 */
public final class APDU {

    /** Protocol and state constants */
    public static final byte STATE_INITIAL              = (byte) 0;
    public static final byte STATE_PARTIAL_INCOMING     = (byte) 1;
    public static final byte STATE_FULL_INCOMING        = (byte) 2;
    public static final byte STATE_OUTGOING             = (byte) 3;
    public static final byte STATE_OUTGOING_LENGTH_KNOWN = (byte) 4;
    public static final byte STATE_PARTIAL_OUTGOING     = (byte) 5;
    public static final byte STATE_FULL_OUTGOING        = (byte) 6;
    public static final byte STATE_ERROR_NO_T0_GETRESPONSE = (byte) 0xFB;

    public static final byte PROTOCOL_T0               = (byte) 0x00;
    public static final byte PROTOCOL_T1               = (byte) 0x01;
    public static final byte PROTOCOL_MEDIA_DEFAULT    = (byte) 0x00;
    public static final byte PROTOCOL_MEDIA_CONTACTLESS_TYPE_A = (byte) 0x80;
    public static final byte PROTOCOL_MEDIA_CONTACTLESS_TYPE_B = (byte) 0x81;

    private final byte[] buffer;

    private APDU() {
        buffer = new byte[256];
    }

    public byte[] getBuffer() { return buffer; }

    public byte getProtocol() { return PROTOCOL_T0; }

    public short setIncomingAndReceive() { return (short) (buffer[ISO7816.OFFSET_LC] & 0xFF); }

    public short receiveBytes(short bOff) { return (short) 0; }

    public void setOutgoing() {}

    public void setOutgoingNoChaining() {}

    public void setOutgoingLength(short len) {}

    public void sendBytes(short bOff, short len) {}

    public void sendBytesLong(byte[] outData, short bOff, short len) {}

    public static APDU getCurrentAPDU() { return new APDU(); }

    public static byte[] getCurrentAPDUBuffer() { return getCurrentAPDU().getBuffer(); }

    public byte getNAD() { return (byte) 0; }

    public short getIncomingLength() {
        return (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
    }
}
