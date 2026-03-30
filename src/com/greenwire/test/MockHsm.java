/*
 * GREENWIRE – Mock HSM (Hardware Security Module)
 * Copyright (C) 2026  GREENWIRE contributors
 * Licensed under GPL-2.0-or-later – see LICENSE.
 */
package com.greenwire.test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;

/**
 * MockHsm – pure-software Hardware Security Module for EMV cryptogram
 * computation and verification.
 *
 * <p>Implements the EMV Application Cryptogram (AC) using:</p>
 * <ol>
 *   <li>Session-key derivation from a master key + ATC (following the
 *       EMV common session-key derivation method).</li>
 *   <li>AC computation via 3DES Retail-MAC (ISO 9797-1, Algorithm 3,
 *       Padding Method 1) over the concatenation of ATC + Unpredictable
 *       Number + optional PDOL data.</li>
 * </ol>
 *
 * <p>The default master key is the NXP JCOP lab / test key
 * {@code 404142434445464748494A4B4C4D4E4F} – suitable for
 * development/testing only; never use in production.</p>
 */
public final class MockHsm {

    /**
     * NXP JCOP default lab key (16 bytes / 2DES).
     * Source: NXP JCOP product documentation / usmartcards.com.
     */
    public static final byte[] JCOP_LAB_KEY = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F
    };

    private final byte[] masterKey;

    /** Create a MockHsm using the default JCOP lab master key. */
    public MockHsm() {
        this(JCOP_LAB_KEY);
    }

    /**
     * Create a MockHsm with a custom master key.
     *
     * @param masterKey 16-byte (2DES) or 24-byte (3DES) master key
     * @throws IllegalArgumentException if the key length is invalid
     */
    public MockHsm(byte[] masterKey) {
        if (masterKey.length != 16 && masterKey.length != 24) {
            throw new IllegalArgumentException(
                    "Master key must be 16 or 24 bytes, got " + masterKey.length);
        }
        this.masterKey = Arrays.copyOf(masterKey, masterKey.length);
    }

    // ------------------------------------------------------------------
    //  Public API
    // ------------------------------------------------------------------

    /**
     * Derive a 16-byte session key from the master key and a 2-byte ATC.
     *
     * <p>Follows the EMV common session-key derivation scheme:</p>
     * <pre>
     *   SK_left  = 3DES_K(ATC || 00 00 00 00 00 00 F0 01)
     *   SK_right = 3DES_K(ATC || 00 00 00 00 00 00 0F 01)
     *   SK = SK_left || SK_right
     * </pre>
     *
     * @param atc 2-byte Application Transaction Counter
     * @return 16-byte session key
     */
    public byte[] deriveSessionKey(byte[] atc) throws Exception {
        byte[] left  = { atc[0], atc[1], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        byte[] right = { atc[0], atc[1], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        left[6]  = (byte) 0xF0;
        left[7]  = 0x01;
        right[6] = (byte) 0x0F;
        right[7] = 0x01;

        byte[] leftEnc  = tripleDesEcbEncrypt(left, masterKey);
        byte[] rightEnc = tripleDesEcbEncrypt(right, masterKey);

        byte[] sessionKey = new byte[16];
        System.arraycopy(leftEnc,  0, sessionKey, 0, 8);
        System.arraycopy(rightEnc, 0, sessionKey, 8, 8);
        return sessionKey;
    }

    /**
     * Compute an 8-byte Application Cryptogram.
     *
     * @param atc  2-byte Application Transaction Counter
     * @param un   4-byte Unpredictable Number from terminal
     * @param pdol additional PDOL / transaction data (may be {@code null})
     * @return 8-byte Application Cryptogram
     */
    public byte[] computeAC(byte[] atc, byte[] un, byte[] pdol) throws Exception {
        byte[] sessionKey = deriveSessionKey(atc);

        // Build MAC input: ATC(2) + UN(4) + PDOL data
        int pdolLen = (pdol != null) ? pdol.length : 0;
        byte[] input = new byte[6 + pdolLen];
        input[0] = atc[0];
        input[1] = atc[1];
        System.arraycopy(un, 0, input, 2, 4);
        if (pdol != null) {
            System.arraycopy(pdol, 0, input, 6, pdolLen);
        }

        return retailMac3DES(input, sessionKey);
    }

    /**
     * Verify an Application Cryptogram produced by the card.
     *
     * @param atc  ATC used during the transaction
     * @param un   Unpredictable Number sent by the terminal
     * @param pdol PDOL data (may be {@code null})
     * @param ac   the 8-byte AC received from the card
     * @return {@code true} if the AC is valid
     */
    public boolean verifyAC(byte[] atc, byte[] un, byte[] pdol, byte[] ac)
            throws Exception {
        byte[] expected = computeAC(atc, un, pdol);
        return Arrays.equals(expected, ac);
    }

    // ------------------------------------------------------------------
    //  Crypto primitives
    // ------------------------------------------------------------------

    /**
     * 3DES ECB encrypt a single 8-byte block.
     *
     * @param block 8-byte data block
     * @param key   16-byte (2DES) or 24-byte (3DES) key
     * @return 8-byte encrypted block
     */
    public byte[] tripleDesEcbEncrypt(byte[] block, byte[] key) throws Exception {
        byte[] key24 = expandTo24(key);
        SecretKeySpec keySpec = new SecretKeySpec(key24, "DESede");
        javax.crypto.Cipher cipher =
                javax.crypto.Cipher.getInstance("DESede/ECB/NoPadding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(block);
    }

    /**
     * ISO 9797-1 Retail MAC (Algorithm 3, Padding Method 1).
     *
     * <ol>
     *   <li>Zero-pad the data to an 8-byte boundary.</li>
     *   <li>Single-DES CBC (key K1 = first 8 bytes of the session key)
     *       over all blocks.</li>
     *   <li>3DES encrypt the last CBC output block with the full session key.</li>
     * </ol>
     *
     * @param data data to MAC (any length)
     * @param key  16-byte session key
     * @return 8-byte MAC
     */
    public byte[] retailMac3DES(byte[] data, byte[] key) throws Exception {
        // Step 1: ISO Padding Method 1 – zero-pad to 8-byte block boundary
        int paddedLen = ((data.length + 7) / 8) * 8;
        byte[] padded = Arrays.copyOf(data, paddedLen);  // trailing zeros

        // Step 2: Single-DES CBC over all blocks with K1
        byte[] k1 = Arrays.copyOf(key, 8);
        SecretKeySpec k1Spec = new SecretKeySpec(k1, "DES");
        javax.crypto.Cipher desCbc =
                javax.crypto.Cipher.getInstance("DES/CBC/NoPadding");
        desCbc.init(javax.crypto.Cipher.ENCRYPT_MODE, k1Spec,
                    new IvParameterSpec(new byte[8]));
        byte[] cbcOut = desCbc.doFinal(padded);

        // Step 3: 3DES encrypt the last 8-byte block of the CBC output
        byte[] lastBlock = Arrays.copyOfRange(cbcOut, cbcOut.length - 8, cbcOut.length);
        return tripleDesEcbEncrypt(lastBlock, key);
    }

    // ------------------------------------------------------------------

    /** Expand a 16-byte 2DES key to a 24-byte 3DES key (K3 = K1). */
    private static byte[] expandTo24(byte[] key) {
        if (key.length == 24) return key;
        byte[] k24 = new byte[24];
        System.arraycopy(key, 0, k24, 0, 16);
        System.arraycopy(key, 0, k24, 16, 8);   // K3 = K1
        return k24;
    }
}
