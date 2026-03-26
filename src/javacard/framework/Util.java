/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.Util – provides array / data manipulation utilities.
 */
public final class Util {

    private Util() {}

    public static short makeShort(byte b1, byte b2) {
        return (short) (((b1 & 0xFF) << 8) | (b2 & 0xFF));
    }

    public static byte getByteHigh(short sValue) {
        return (byte) ((sValue >> 8) & 0xFF);
    }

    public static byte getByteLow(short sValue) {
        return (byte) (sValue & 0xFF);
    }

    public static short arrayCopy(byte[] src, short srcOff,
                                   byte[] dest, short destOff, short length) {
        System.arraycopy(src, srcOff, dest, destOff, length);
        return (short) (destOff + length);
    }

    public static short arrayCopyNonAtomic(byte[] src, short srcOff,
                                            byte[] dest, short destOff, short length) {
        System.arraycopy(src, srcOff, dest, destOff, length);
        return (short) (destOff + length);
    }

    public static short arrayFillNonAtomic(byte[] bArray, short bOff,
                                            short bLen, byte bValue) {
        for (short i = 0; i < bLen; i++) {
            bArray[(short) (bOff + i)] = bValue;
        }
        return (short) (bOff + bLen);
    }

    public static byte arrayCompare(byte[] src, short srcOff,
                                     byte[] dest, short destOff, short length) {
        for (short i = 0; i < length; i++) {
            int diff = (src[(short)(srcOff+i)] & 0xFF) - (dest[(short)(destOff+i)] & 0xFF);
            if (diff != 0) return (byte) (diff < 0 ? -1 : 1);
        }
        return (byte) 0;
    }

    public static short setShort(byte[] bArray, short bOff, short sValue) {
        bArray[bOff]              = (byte) ((sValue >> 8) & 0xFF);
        bArray[(short)(bOff + 1)] = (byte) (sValue & 0xFF);
        return (short) (bOff + 2);
    }

    public static short getShort(byte[] bArray, short bOff) {
        return makeShort(bArray[bOff], bArray[(short)(bOff + 1)]);
    }
}
