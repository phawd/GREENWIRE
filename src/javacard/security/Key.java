/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.security;

/**
 * Stub for javacard.security.Key – base interface for all Java Card key types.
 */
public interface Key {

    boolean isInitialized();

    void clearKey();

    byte getType();

    short getSize();
}
