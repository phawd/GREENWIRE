/*
 * GREENWIRE - Java Card compilation stub
 *
 * Based on the Java Card 3.0.5 Classic Edition API specification,
 * javacardx.crypto.Cipher class.
 */
package javacardx.crypto;

import javacard.security.CryptoException;
import javacard.security.Key;

/**
 * Compilation stub for {@code javacardx.crypto.Cipher}.
 *
 * <p>Provides an abstract class that enumerates the cipher algorithms available
 * on a Java Card platform and declares the interface for encrypt / decrypt
 * operations.  Only constants and method signatures are defined here; a real
 * Java Card runtime would supply the native implementation.</p>
 */
public abstract class Cipher {

    /* ------------------------------------------------------------------ */
    /*  Algorithm constants                                                 */
    /* ------------------------------------------------------------------ */

    /** No padding. */
    public static final byte ALG_DES_CBC_NOPAD          = 1;
    /** ISO 9797 M1 padding. */
    public static final byte ALG_DES_CBC_ISO9797_M1     = 2;
    /** ISO 9797 M2 padding. */
    public static final byte ALG_DES_CBC_ISO9797_M2     = 3;
    /** PKCS#5 padding. */
    public static final byte ALG_DES_CBC_PKCS5          = 4;
    /** DES ECB, no padding. */
    public static final byte ALG_DES_ECB_NOPAD          = 5;
    /** DES ECB, ISO 9797 M1 padding. */
    public static final byte ALG_DES_ECB_ISO9797_M1     = 6;
    /** DES ECB, ISO 9797 M2 padding. */
    public static final byte ALG_DES_ECB_ISO9797_M2     = 7;
    /** DES ECB, PKCS#5 padding. */
    public static final byte ALG_DES_ECB_PKCS5          = 8;
    /** RSA PKCS#1 v1.5. */
    public static final byte ALG_RSA_PKCS1              = 9;
    /** RSA, no padding (raw). */
    public static final byte ALG_RSA_NOPAD              = 12;
    /** RSA OAEP (PKCS#1 v2.0). */
    public static final byte ALG_RSA_PKCS1_OAEP         = 10;
    /** AES CBC, no padding. */
    public static final byte ALG_AES_BLOCK_128_CBC_NOPAD = 13;
    /** AES CBC, ISO 9797 M2 padding. */
    public static final byte ALG_AES_BLOCK_128_CBC_ISO9797_M2 = 14;
    /** AES ECB, no padding. */
    public static final byte ALG_AES_BLOCK_128_ECB_NOPAD = 15;
    /** AES ECB, ISO 9797 M2 padding. */
    public static final byte ALG_AES_BLOCK_128_ECB_ISO9797_M2 = 16;
    /** AES CBC, ISO 9797 M2 padding (variable key size). */
    public static final byte ALG_AES_CBC_ISO9797_M2     = 17;
    /** AES-CTR. */
    public static final byte ALG_AES_CTR                = 18;
    /** AES-CCM. */
    public static final byte ALG_AES_CCM                = 19;
    /** AES-GCM. */
    public static final byte ALG_AES_GCM                = 20;

    /** Mode constant: encrypt. */
    public static final byte MODE_ENCRYPT = 1;
    /** Mode constant: decrypt. */
    public static final byte MODE_DECRYPT = 2;

    /* ------------------------------------------------------------------ */
    /*  Factory method                                                      */
    /* ------------------------------------------------------------------ */

    /**
     * Create a {@code Cipher} instance for the given algorithm.
     *
     * @param algorithm    one of the {@code ALG_*} constants
     * @param externalAccess {@code true} if the cipher will be shared across applets
     * @return a new {@code Cipher} instance
     * @throws CryptoException {@link CryptoException#NO_SUCH_ALGORITHM} if the
     *         algorithm is not supported
     */
    public static final Cipher getInstance(byte algorithm, boolean externalAccess)
            throws CryptoException {
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        return null; // unreachable – here only for compilation
    }

    /* ------------------------------------------------------------------ */
    /*  Abstract interface                                                  */
    /* ------------------------------------------------------------------ */

    /**
     * Initialise the cipher for an encrypt or decrypt operation.
     *
     * @param theKey  the key to use
     * @param theMode {@link #MODE_ENCRYPT} or {@link #MODE_DECRYPT}
     * @throws CryptoException if the key type is incompatible with the algorithm
     */
    public abstract void init(Key theKey, byte theMode) throws CryptoException;

    /**
     * Initialise the cipher with an explicit IV / parameter block.
     *
     * @param theKey   the key to use
     * @param theMode  {@link #MODE_ENCRYPT} or {@link #MODE_DECRYPT}
     * @param bArray   buffer containing IV or other initialisation data
     * @param bOff     offset within {@code bArray}
     * @param bLen     length of the initialisation data
     * @throws CryptoException if initialisation fails
     */
    public abstract void init(Key theKey, byte theMode,
                               byte[] bArray, short bOff, short bLen)
            throws CryptoException;

    /**
     * Process data (may be called repeatedly for chunked input).
     *
     * @param inBuf   input buffer
     * @param inOff   offset within {@code inBuf}
     * @param inLen   number of bytes to process
     * @param outBuf  output buffer
     * @param outOff  offset within {@code outBuf}
     * @return number of bytes written to {@code outBuf}
     * @throws CryptoException if processing fails
     */
    public abstract short update(byte[] inBuf, short inOff, short inLen,
                                  byte[] outBuf, short outOff)
            throws CryptoException;

    /**
     * Process the final block of data.
     *
     * @param inBuf   input buffer
     * @param inOff   offset within {@code inBuf}
     * @param inLen   number of bytes to process
     * @param outBuf  output buffer
     * @param outOff  offset within {@code outBuf}
     * @return number of bytes written to {@code outBuf}
     * @throws CryptoException if processing or padding fails
     */
    public abstract short doFinal(byte[] inBuf, short inOff, short inLen,
                                   byte[] outBuf, short outOff)
            throws CryptoException;

    /**
     * @return the algorithm constant for this cipher instance
     */
    public abstract byte getAlgorithm();
}
