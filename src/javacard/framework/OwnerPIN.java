/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.OwnerPIN – concrete implementation of {@link PIN}
 * for cardholder verification.
 *
 * <p>OwnerPIN stores and validates a PIN value and tracks remaining tries.
 * After {@code maxTries} incorrect attempts the PIN is blocked until
 * {@link #resetAndUnblock()} is called (or the card is reset, depending on
 * applet logic).</p>
 */
public class OwnerPIN implements PIN {

    private final byte maxTries;
    private byte triesRemaining;
    private byte[] pin;
    private byte pinLength;
    private boolean validated;

    /**
     * Create a new OwnerPIN.
     *
     * @param tryLimit   maximum number of incorrect PIN presentations allowed
     * @param maxPINSize maximum length of the PIN in bytes
     * @throws PINException if {@code tryLimit} or {@code maxPINSize} is 0
     */
    public OwnerPIN(byte tryLimit, byte maxPINSize) {
        if (tryLimit == 0 || maxPINSize == 0) {
            PINException.throwIt(PINException.ILLEGAL_VALUE);
        }
        this.maxTries       = tryLimit;
        this.triesRemaining = tryLimit;
        this.pin            = new byte[maxPINSize & 0xFF];
        this.pinLength      = 0;
        this.validated      = false;
    }

    /**
     * Update the PIN value.  Resets the try-counter and clears the validated flag.
     *
     * @param pin    byte array containing the new PIN
     * @param offset offset within {@code pin} of the first PIN byte
     * @param length number of bytes in the new PIN
     * @throws PINException if {@code length} exceeds the maximum PIN size
     */
    public void update(byte[] pin, short offset, byte length) {
        if (length > (byte) this.pin.length) {
            PINException.throwIt(PINException.ILLEGAL_VALUE);
        }
        Util.arrayCopyNonAtomic(pin, offset, this.pin, (short) 0, (short) (length & 0xFF));
        this.pinLength   = length;
        this.triesRemaining = maxTries;
        this.validated   = false;
    }

    /**
     * Validate a presented PIN value.
     *
     * @param pin    byte array containing the presented PIN
     * @param offset offset within {@code pin} of the first PIN byte
     * @param length length of the presented PIN
     * @return {@code true} if the PIN matches; {@code false} otherwise
     */
    @Override
    public boolean check(byte[] pin, short offset, byte length) {
        if (triesRemaining == 0) {
            return false;
        }
        if (length != pinLength) {
            triesRemaining--;
            validated = false;
            return false;
        }
        if (Util.arrayCompare(pin, offset, this.pin, (short) 0, (short) (length & 0xFF)) == 0) {
            triesRemaining = maxTries;
            validated = true;
            return true;
        }
        triesRemaining--;
        validated = false;
        return false;
    }

    /**
     * @return number of PIN verification attempts remaining
     */
    @Override
    public byte getTriesRemaining() {
        return triesRemaining;
    }

    /**
     * @return {@code true} if the PIN has been successfully verified this session
     */
    @Override
    public boolean isValidated() {
        return validated;
    }

    /**
     * Reset the validated flag (called on deselect).
     */
    @Override
    public void reset() {
        validated = false;
    }

    /**
     * Reset the try-counter and clear the validated flag (unblock a blocked PIN).
     */
    public void resetAndUnblock() {
        triesRemaining = maxTries;
        validated = false;
    }
}
