/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.AID – encapsulates an ISO 7816 Application Identifier.
 */
public class AID {

    private final byte[] aid;

    public AID(byte[] bArray, short offset, byte length) {
        aid = new byte[length];
        Util.arrayCopy(bArray, offset, aid, (short) 0, length);
    }

    public final boolean equals(AID otherAID) {
        if (otherAID == null) return false;
        return Util.arrayCompare(aid, (short) 0,
                otherAID.aid, (short) 0, (short) aid.length) == 0;
    }

    public final boolean equals(byte[] bArray, short offset, byte length) {
        if (length != (byte) aid.length) return false;
        return Util.arrayCompare(aid, (short) 0, bArray, offset, (short) (length & 0xFF)) == 0;
    }

    public final byte getBytes(byte[] dest, short offset) {
        Util.arrayCopy(aid, (short) 0, dest, offset, (short) aid.length);
        return (byte) aid.length;
    }

    public final boolean RIDEquals(AID otherAID) {
        if (otherAID == null) return false;
        return Util.arrayCompare(aid, (short) 0,
                otherAID.aid, (short) 0, (short) 5) == 0;
    }
}
