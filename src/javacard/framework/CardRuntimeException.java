/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.CardRuntimeException – base unchecked exception for Java Card.
 */
public class CardRuntimeException extends RuntimeException {

    private short sw;

    public CardRuntimeException(short reason) {
        this.sw = reason;
    }

    public short getReason() { return sw; }

    public void setReason(short reason) { this.sw = reason; }
}
