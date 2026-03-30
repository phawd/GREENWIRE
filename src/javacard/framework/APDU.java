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
    private final byte[] responseBuffer;
    private short responseLength;

    private APDU() {
        buffer         = new byte[256];
        responseBuffer = new byte[256];
        responseLength = 0;
    }

    /**
     * Create an APDU pre-loaded with command bytes for simulation / testing.
     * Not available on a real Java Card runtime.
     *
     * @param apduBytes raw command bytes (CLA INS P1 P2 [Lc data])
     * @return a new APDU whose buffer is populated with {@code apduBytes}
     */
    public static APDU createForTest(byte[] apduBytes) {
        APDU apdu = new APDU();
        int len = Math.min(apduBytes.length, apdu.buffer.length);
        System.arraycopy(apduBytes, 0, apdu.buffer, 0, len);
        return apdu;
    }

    public byte[] getBuffer() { return buffer; }

    public byte getProtocol() { return PROTOCOL_MEDIA_CONTACTLESS_TYPE_A; }

    public short setIncomingAndReceive() { return (short) (buffer[ISO7816.OFFSET_LC] & 0xFF); }

    public short receiveBytes(short bOff) { return (short) 0; }

    public void setOutgoing() { responseLength = 0; }

    public void setOutgoingNoChaining() { responseLength = 0; }

    public void setOutgoingLength(short len) { responseLength = len; }

    public void sendBytes(short bOff, short len) {
        System.arraycopy(buffer, bOff, responseBuffer, 0, len);
        responseLength = len;
    }

    public void sendBytesLong(byte[] outData, short bOff, short len) {
        System.arraycopy(outData, bOff, responseBuffer, 0, len);
        responseLength = len;
    }

    /**
     * Return the response data captured by {@link #sendBytesLong} /
     * {@link #sendBytes}.  Only meaningful after applet processing has
     * completed in a simulation context.
     */
    public byte[] getResponseData() {
        byte[] result = new byte[responseLength];
        System.arraycopy(responseBuffer, 0, result, 0, responseLength);
        return result;
    }

    public static APDU getCurrentAPDU() { return new APDU(); }

    public static byte[] getCurrentAPDUBuffer() { return getCurrentAPDU().getBuffer(); }

    public byte getNAD() { return (byte) 0; }

    public short getIncomingLength() {
        return (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
    }
}
