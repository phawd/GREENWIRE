/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.PIN – interface for PIN validation objects.
 */
public interface PIN {

    boolean check(byte[] pin, short offset, byte length);

    byte getTriesRemaining();

    boolean isValidated();

    void reset();
}
