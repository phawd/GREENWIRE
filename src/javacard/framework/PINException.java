/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.PINException – thrown for PIN operation errors.
 */
public class PINException extends CardRuntimeException {

    public static final short ILLEGAL_VALUE = (short) 1;
    public static final short ILLEGAL_STATE = (short) 2;

    public PINException(short reason) {
        super(reason);
    }

    public static void throwIt(short reason) {
        throw new PINException(reason);
    }
}
