/*
 * GREENWIRE – Terminal Emulator
 * Copyright (C) 2026  GREENWIRE contributors
 * Licensed under GPL-2.0-or-later – see LICENSE.
 */
package com.greenwire.test;

import java.util.Arrays;
import java.util.Random;

/**
 * TerminalEmulator builds and sends standard EMV Contactless APDUs to a
 * {@link AppletTestHarness}, modelling the behaviour of an acquiring
 * POS terminal.
 *
 * <p>The supported transaction steps are:</p>
 * <ol>
 *   <li>{@link #selectApplication()} – SELECT by AID</li>
 *   <li>{@link #getProcessingOptions()} – GET PROCESSING OPTIONS</li>
 *   <li>{@link #readRecord(int, int)} – READ RECORD</li>
 *   <li>{@link #verifyPin(byte[])} – VERIFY (online PIN)</li>
 *   <li>{@link #generateAC(byte, byte[])} – GENERATE AC</li>
 *   <li>{@link #getData(byte, byte)} – GET DATA</li>
 * </ol>
 *
 * <p>Each method returns the raw APDU response (data + SW).</p>
 */
public final class TerminalEmulator {

    /** GREENWIRE Applet AID (Visa RID + proprietary PIX). */
    public static final byte[] APPLET_AID = {
        (byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x49, 0x10, 0x01
    };

    /** Cryptogram Reference Control Parameter: TC (offline approved). */
    public static final byte CRCP_TC  = (byte) 0x40;
    /** Cryptogram Reference Control Parameter: ARQC (online request). */
    public static final byte CRCP_ARQC = (byte) 0x80;

    private final AppletTestHarness harness;
    private final Random rng;

    /** ATC returned from the last GENERATE AC response. */
    private byte[] lastAtc = new byte[2];
    /** AC (Application Cryptogram) from the last GENERATE AC response. */
    private byte[] lastAc  = new byte[8];
    /** Unpredictable Number used in the last GENERATE AC command. */
    private byte[] lastUn  = new byte[4];

    public TerminalEmulator(AppletTestHarness harness) {
        this.harness = harness;
        this.rng     = new Random();
    }

    // ------------------------------------------------------------------
    //  Transaction steps (card ← terminal direction)
    // ------------------------------------------------------------------

    /**
     * SELECT application by AID (00 A4 04 00 Lc AID).
     */
    public byte[] selectApplication() {
        byte[] apdu = new byte[5 + APPLET_AID.length];
        apdu[0] = 0x00;          // CLA
        apdu[1] = (byte) 0xA4;  // INS SELECT
        apdu[2] = 0x04;          // P1 – select by DF name
        apdu[3] = 0x00;          // P2
        apdu[4] = (byte) APPLET_AID.length; // Lc
        System.arraycopy(APPLET_AID, 0, apdu, 5, APPLET_AID.length);
        return harness.sendCommand(apdu);
    }

    /**
     * GET PROCESSING OPTIONS (80 A8 00 00 02 83 00).
     *
     * <p>The PDOL is empty (tag 83, length 00).</p>
     */
    public byte[] getProcessingOptions() {
        return harness.sendCommand(new byte[]{
            (byte) 0x00,         // CLA
            (byte) 0xA8,         // INS GPO
            (byte) 0x00,         // P1
            (byte) 0x00,         // P2
            (byte) 0x02,         // Lc
            (byte) 0x83, 0x00    // empty PDOL
        });
    }

    /**
     * READ RECORD (00 B2 recordNum (SFI<<3|04) 00).
     *
     * @param sfi       Short File Identifier (1–30)
     * @param recordNum record number (1-based)
     */
    public byte[] readRecord(int sfi, int recordNum) {
        return harness.sendCommand(new byte[]{
            (byte) 0x00,                           // CLA
            (byte) 0xB2,                           // INS READ RECORD
            (byte) recordNum,                      // P1 – record number
            (byte) ((sfi << 3) | 0x04),            // P2 – (SFI<<3)|04
            (byte) 0x00                            // Le
        });
    }

    /**
     * VERIFY PIN (00 20 00 80 Lc PIN...).
     *
     * @param pin raw PIN bytes (e.g. {0x30, 0x30, 0x30, 0x30} for "0000")
     */
    public byte[] verifyPin(byte[] pin) {
        byte[] apdu = new byte[5 + pin.length];
        apdu[0] = 0x00;          // CLA
        apdu[1] = 0x20;          // INS VERIFY
        apdu[2] = 0x00;          // P1
        apdu[3] = (byte) 0x80;  // P2 – offline plain PIN
        apdu[4] = (byte) pin.length;
        System.arraycopy(pin, 0, apdu, 5, pin.length);
        return harness.sendCommand(apdu);
    }

    /**
     * GENERATE AC (80 AE CRCP 00 1D CDOL1-data).
     *
     * <p>Builds a minimal 29-byte CDOL1 data field and generates a
     * fresh 4-byte Unpredictable Number for each call.</p>
     *
     * @param crcp Cryptogram Reference Control Parameter
     *             ({@link #CRCP_TC} or {@link #CRCP_ARQC})
     * @param transactionAmount 4-byte big-endian transaction amount
     */
    public byte[] generateAC(byte crcp, byte[] transactionAmount) {
        // CDOL1 = 29 bytes:
        //   Amount (4) + Other Amount (4) + Terminal Country (2) +
        //   TVR (5) + Currency Code (2) + Transaction Date (3) +
        //   Transaction Type (1) + Unpredictable Number (4) +
        //   AIP (2) + Terminal Capabilities (3) - but we'll use a
        //   flat 29-byte block with UN at offset 25 as expected by the applet.
        byte[] cdol = new byte[29];
        // Amount
        System.arraycopy(transactionAmount, 0, cdol, 0,
                         Math.min(4, transactionAmount.length));
        // Terminal Country Code (IE = 0x0372 at offsets 8-9)
        cdol[8]  = 0x03;
        cdol[9]  = 0x72;
        // TVR (5 bytes, all zeros = approved offline)
        // Transaction Date (YY MM DD at offsets 19-21)
        cdol[19] = 0x26; // year
        cdol[20] = 0x03; // month
        cdol[21] = 0x30; // day
        // Transaction Type (0x00 = purchase at offset 22)
        // Unpredictable Number (4 bytes at offsets 25-28)
        rng.nextBytes(lastUn);
        System.arraycopy(lastUn, 0, cdol, 25, 4);

        byte[] apdu = new byte[5 + cdol.length];
        apdu[0] = (byte) 0x00;   // CLA
        apdu[1] = (byte) 0xAE;   // INS GENERATE AC
        apdu[2] = crcp;           // P1 = CRCP
        apdu[3] = 0x00;           // P2
        apdu[4] = (byte) cdol.length; // Lc
        System.arraycopy(cdol, 0, apdu, 5, cdol.length);

        byte[] resp = harness.sendCommand(apdu);

        // Parse and cache ATC + AC from the response if successful
        if (AppletTestHarness.isOk(resp)) {
            parseGenerateAcResponse(AppletTestHarness.data(resp));
        }
        return resp;
    }

    /**
     * GET DATA (00 CA tagHigh tagLow 00).
     *
     * @param tagHigh high byte of the data object tag
     * @param tagLow  low byte of the data object tag
     */
    public byte[] getData(byte tagHigh, byte tagLow) {
        return harness.sendCommand(new byte[]{
            (byte) 0x00,   // CLA
            (byte) 0xCA,   // INS GET DATA
            tagHigh,
            tagLow,
            (byte) 0x00    // Le
        });
    }

    // ------------------------------------------------------------------
    //  Accessors for last transaction data
    // ------------------------------------------------------------------

    /** Return the ATC from the most recent GENERATE AC response. */
    public byte[] getLastAtc() { return Arrays.copyOf(lastAtc, lastAtc.length); }

    /** Return the Application Cryptogram from the most recent GENERATE AC. */
    public byte[] getLastAc() { return Arrays.copyOf(lastAc, lastAc.length); }

    /** Return the Unpredictable Number used in the most recent GENERATE AC. */
    public byte[] getLastUn() { return Arrays.copyOf(lastUn, lastUn.length); }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    /**
     * Parse tag 9F36 (ATC) and 9F26 (AC) from a GENERATE AC Format-2
     * response template (tag 77).
     */
    private void parseGenerateAcResponse(byte[] data) {
        // Minimal BER-TLV scan for 9F36 and 9F26
        int i = 0;
        if (data.length < 2 || data[0] != 0x77) return;
        int templateLen = data[1] & 0xFF;
        i = 2;
        int end = Math.min(i + templateLen, data.length);
        while (i < end - 2) {
            int t1 = data[i] & 0xFF;
            int t2 = data[i + 1] & 0xFF;
            int len = data[i + 2] & 0xFF;
            // 9F36 – ATC
            if (t1 == 0x9F && t2 == 0x36 && len == 2 && i + 4 < data.length) {
                lastAtc[0] = data[i + 3];
                lastAtc[1] = data[i + 4];
            }
            // 9F26 – AC
            if (t1 == 0x9F && t2 == 0x26 && len == 8 && i + 10 < data.length) {
                System.arraycopy(data, i + 3, lastAc, 0, 8);
            }
            i += 3 + len;
        }
    }
}
