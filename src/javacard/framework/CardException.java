/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.CardException – base checked exception for Java Card.
 */
public class CardException extends Exception {

    private short sw;

    public CardException(short reason) {
        this.sw = reason;
    }

    public short getReason() { return sw; }

    public void setReason(short reason) { this.sw = reason; }
}
