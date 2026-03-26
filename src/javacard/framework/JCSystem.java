/*
 * GREENWIRE - Java Card compilation stub
 * Derived from the Java Card 3.0.5 Classic Edition API specification.
 * Copyright (C) Oracle and/or its affiliates. All rights reserved.
 * Used here as a compilation/reference stub only.
 */
package javacard.framework;

/**
 * Stub for javacard.framework.JCSystem – provides Java Card system services.
 */
public final class JCSystem {

    public static final byte NOT_A_TRANSIENT_OBJECT    = (byte) 0;
    public static final byte CLEAR_ON_RESET            = (byte) 1;
    public static final byte CLEAR_ON_DESELECT         = (byte) 2;

    public static final short JAVACARD_VERSION_2_1     = (short) 0x0201;
    public static final short JAVACARD_VERSION_2_2     = (short) 0x0202;
    public static final short JAVACARD_VERSION_3_0_4   = (short) 0x0304;

    private JCSystem() {}

    public static short getVersion() { return JAVACARD_VERSION_3_0_4; }

    public static byte[] makeTransientByteArray(short length, byte event) {
        return new byte[length];
    }

    public static short[] makeTransientShortArray(short length, byte event) {
        return new short[length];
    }

    public static boolean[] makeTransientBooleanArray(short length, byte event) {
        return new boolean[length];
    }

    public static Object[] makeTransientObjectArray(short length, byte event) {
        return new Object[length];
    }

    public static void beginTransaction() {}
    public static void commitTransaction() {}
    public static void abortTransaction() {}

    public static short getUnusedCommitCapacity() { return (short) 0x7FFF; }

    public static byte isTransient(Object theObj) { return NOT_A_TRANSIENT_OBJECT; }

    public static AID lookupAID(byte[] buffer, short offset, byte length) { return null; }

    public static AID getAID() { return null; }
}
