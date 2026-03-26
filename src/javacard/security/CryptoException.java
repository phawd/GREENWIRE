/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.security;

/**
 * Stub for javacard.security.CryptoException – thrown for cryptographic errors.
 */
public class CryptoException extends javacard.framework.CardRuntimeException {

    public static final short ILLEGAL_VALUE      = (short) 1;
    public static final short UNINITIALIZED_KEY  = (short) 2;
    public static final short NO_SUCH_ALGORITHM  = (short) 3;
    public static final short INVALID_INIT       = (short) 4;
    public static final short ILLEGAL_USE        = (short) 5;

    public CryptoException(short reason) {
        super(reason);
    }

    public static void throwIt(short reason) {
        throw new CryptoException(reason);
    }
}
