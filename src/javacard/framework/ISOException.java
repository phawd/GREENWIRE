/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.ISOException – ISO 7816 status-word exception.
 */
public class ISOException extends CardRuntimeException {

    public ISOException(short sw) {
        super(sw);
    }

    public static void throwIt(short sw) {
        throw new ISOException(sw);
    }
}
