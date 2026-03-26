/*
 * GREENWIRE – Google Wallet NFC / EMV Card Emulation Applet
 * Copyright (C) 2026  GREENWIRE contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
package com.greenwire.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacardx.crypto.Cipher;

/**
 * GREENWIRE Wallet Applet – Java Card applet implementing a subset of the
 * EMV Contactless (Google Wallet / Visa payWave / Mastercard PayPass) protocol
 * for NFC card emulation.
 *
 * <h2>Supported instructions</h2>
 * <ul>
 *   <li>{@code SELECT} (INS A4) – application selection by AID</li>
 *   <li>{@code GET PROCESSING OPTIONS} (INS A8) – initiate EMV transaction</li>
 *   <li>{@code READ RECORD} (INS B2) – read card data records</li>
 *   <li>{@code VERIFY} (INS 20) – cardholder PIN verification</li>
 *   <li>{@code GENERATE AC} (INS AE) – generate application cryptogram</li>
 *   <li>{@code GET DATA} (INS CA) – retrieve data objects</li>
 * </ul>
 *
 * <h2>Security notes</h2>
 * <ul>
 *   <li>PIN is stored as an {@link OwnerPIN} with a configurable try limit.</li>
 *   <li>The applet key material must be loaded via a secure channel before
 *       any contactless transaction can be authorised.</li>
 * </ul>
 */
public final class GreenWireApplet extends Applet implements ISO7816 {

    /* ------------------------------------------------------------------ */
    /*  Applet AID (Proprietary – RID 0xA000000003 + PIX 0x1049 0x10 0x01)*/
    /* ------------------------------------------------------------------ */
    private static final byte[] APPLET_AID = {
        (byte) 0xA0, 0x00, 0x00, 0x00, 0x03,   // RID – Visa
        0x10, 0x49, 0x10, 0x01                  // PIX
    };

    /* ------------------------------------------------------------------ */
    /*  EMV instruction codes                                              */
    /* ------------------------------------------------------------------ */
    private static final byte INS_GPO         = (byte) 0xA8;
    private static final byte INS_GENERATE_AC = (byte) 0xAE;
    private static final byte INS_GET_DATA_EMV = (byte) 0xCA;

    /* ------------------------------------------------------------------ */
    /*  EMV tag constants used in response TLV data                        */
    /* ------------------------------------------------------------------ */
    /** Application Interchange Profile */
    private static final byte TAG_AIP_HIGH = (byte) 0x82;
    /** AFL – Application File Locator */
    private static final byte TAG_AFL      = (byte) 0x94;
    /** Cryptogram Information Data */
    private static final byte TAG_CID      = (byte) 0x9F;
    private static final byte TAG_CID_LOW  = (byte) 0x27;
    /** Application Transaction Counter */
    private static final byte TAG_ATC_HIGH = (byte) 0x9F;
    private static final byte TAG_ATC_LOW  = (byte) 0x36;
    /** Application Cryptogram */
    private static final byte TAG_AC_HIGH  = (byte) 0x9F;
    private static final byte TAG_AC_LOW   = (byte) 0x26;

    /* ------------------------------------------------------------------ */
    /*  PIN configuration                                                   */
    /* ------------------------------------------------------------------ */
    private static final byte PIN_TRY_LIMIT  = (byte) 3;
    private static final byte PIN_MAX_LENGTH = (byte) 8;

    /* ------------------------------------------------------------------ */
    /*  Instance state                                                      */
    /* ------------------------------------------------------------------ */
    /** Cardholder PIN managed by the Java Card runtime. */
    private final OwnerPIN pin;

    /** Application Transaction Counter (big-endian 2 bytes). */
    private final byte[] atc;

    /** Unpredictable Number from the terminal (transient – cleared on reset). */
    private final byte[] unpredictableNumber;

    /** Cipher for AC generation – allocated once, re-initialised per transaction. */
    private Cipher acCipher;

    /** Whether the applet has been personalised (keys loaded). */
    private boolean personalised;

    /* ------------------------------------------------------------------ */
    /*  Constructor / install                                               */
    /* ------------------------------------------------------------------ */

    private GreenWireApplet(byte[] bArray, short bOffset, byte bLength) {
        pin                = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_LENGTH);
        atc                = new byte[2];
        unpredictableNumber = JCSystem.makeTransientByteArray((short) 4,
                                JCSystem.CLEAR_ON_RESET);
        personalised       = false;

        // Set default PIN to "0000"
        byte[] defaultPin = { 0x30, 0x30, 0x30, 0x30 };
        pin.update(defaultPin, (short) 0, (byte) defaultPin.length);

        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /**
     * Called by the Java Card runtime to install this applet.
     *
     * @param bArray    install parameter array
     * @param bOffset   offset of AID length byte in {@code bArray}
     * @param bLength   length of install data
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new GreenWireApplet(bArray, bOffset, bLength);
    }

    /* ------------------------------------------------------------------ */
    /*  Applet lifecycle                                                    */
    /* ------------------------------------------------------------------ */

    @Override
    public boolean select() {
        pin.reset();
        return true;
    }

    @Override
    public void deselect() {
        pin.reset();
    }

    /* ------------------------------------------------------------------ */
    /*  APDU dispatch                                                       */
    /* ------------------------------------------------------------------ */

    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();

        // Silently swallow SELECT for this applet
        if (selectingApplet()) return;

        byte cla = buf[OFFSET_CLA];
        byte ins = buf[OFFSET_INS];

        // Only ISO 7816 class byte is accepted
        if (cla != CLA_ISO7816) {
            ISOException.throwIt(SW_CLA_NOT_SUPPORTED);
        }

        switch (ins) {
            case INS_VERIFY:
                processVerify(apdu);
                break;
            case INS_GPO:
                processGetProcessingOptions(apdu);
                break;
            case INS_READ_RECORD:
                processReadRecord(apdu);
                break;
            case INS_GENERATE_AC:
                processGenerateAC(apdu);
                break;
            case INS_GET_DATA_EMV:
                processGetData(apdu);
                break;
            default:
                ISOException.throwIt(SW_INS_NOT_SUPPORTED);
        }
    }

    /* ------------------------------------------------------------------ */
    /*  VERIFY (PIN check)                                                  */
    /* ------------------------------------------------------------------ */

    private void processVerify(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc   = apdu.setIncomingAndReceive();

        if (lc == 0) {
            // Query remaining tries
            if (pin.getTriesRemaining() == 0) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            short sw = (short) (SW_PIN_TRIES_REMAINING | (pin.getTriesRemaining() & 0xFF));
            ISOException.throwIt(sw);
        }

        if (!pin.check(buf, OFFSET_CDATA, (byte) lc)) {
            if (pin.getTriesRemaining() == 0) {
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            ISOException.throwIt(SW_WRONG_DATA);
        }
        // Successful PIN verification – fall through to 9000
    }

    /* ------------------------------------------------------------------ */
    /*  GET PROCESSING OPTIONS                                              */
    /* ------------------------------------------------------------------ */

    private void processGetProcessingOptions(APDU apdu) {
        apdu.setIncomingAndReceive();

        // AIP: SDA + offline static data authentication supported
        // AIP byte 1: 0x18 = offline plaintext PIN + SDA
        // AFL: one record in SFI 1, record 1
        byte[] response = {
            TAG_AIP_HIGH, 0x02, 0x18, 0x00,   // AIP (2 bytes)
            TAG_AFL,       0x04,               // AFL (4 bytes)
                0x08, 0x01, 0x01, 0x00         // SFI=1, first=1, last=1, offline=0
        };

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) response.length);
        apdu.sendBytesLong(response, (short) 0, (short) response.length);
    }

    /* ------------------------------------------------------------------ */
    /*  READ RECORD                                                         */
    /* ------------------------------------------------------------------ */

    private void processReadRecord(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        // P1 = record number, P2 = (SFI << 3) | 0x04
        byte recordNum = buf[OFFSET_P1];
        byte sfi       = (byte) ((buf[OFFSET_P2] >> 3) & 0x1F);

        if (sfi != 1 || recordNum != 1) {
            ISOException.throwIt(SW_RECORD_NOT_FOUND);
        }

        // Minimal EMV record: PAN, expiry, service code
        byte[] record = buildEmvRecord();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) record.length);
        apdu.sendBytesLong(record, (short) 0, (short) record.length);
    }

    /**
     * Build a minimal EMV record (TLV-encoded) for SFI 1, record 1.
     *
     * <p>In a production applet the PAN, expiry date and other sensitive
     * fields would be loaded during personalisation and stored in EEPROM.
     * This stub returns placeholder values to allow the transaction flow to
     * complete.</p>
     */
    private byte[] buildEmvRecord() {
        // 70 (EMV record template) containing:
        //   5A – PAN (8 bytes, BCD-encoded)
        //   5F24 – Expiry Date (YYMMDD packed into 3 bytes)
        //   5F25 – Effective Date
        //   5F28 – Issuer Country Code
        //   5F34 – PAN Sequence Number
        return new byte[] {
            0x70,                                   // record template
            0x1A,                                   // length = 26 bytes
            0x5A, 0x08,                             // PAN tag + length
                (byte) 0x40, 0x12, 0x34, 0x56,
                0x78, (byte) 0x90, 0x12, 0x34,     // placeholder PAN
            0x5F, 0x24, 0x03,                       // expiry date tag + length
                0x27, 0x12, 0x31,                   // YY=27, MM=12, DD=31
            0x5F, 0x25, 0x03,                       // effective date
                0x24, 0x01, 0x01,
            0x5F, 0x28, 0x02,                       // issuer country code (372=Ireland)
                0x03, 0x72,
            0x5F, 0x34, 0x01,                       // PAN sequence number
                0x01
        };
    }

    /* ------------------------------------------------------------------ */
    /*  GENERATE AC                                                         */
    /* ------------------------------------------------------------------ */

    private void processGenerateAC(APDU apdu) {
        short lc = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();

        if (lc < 29) {
            ISOException.throwIt(SW_WRONG_LENGTH);
        }

        // Save the 4-byte Unpredictable Number (bytes 25-28 of the CDOL1 data)
        Util.arrayCopyNonAtomic(buf, (short) (OFFSET_CDATA + 25),
                                unpredictableNumber, (short) 0, (short) 4);

        // Increment ATC
        incrementATC();

        // Build GENERATE AC response: CID (TC=0x40) + ATC + AC (8 bytes placeholder)
        byte[] acResponse = buildACResponse();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) acResponse.length);
        apdu.sendBytesLong(acResponse, (short) 0, (short) acResponse.length);
    }

    private byte[] buildACResponse() {
        // Response Message Template Format 1 (tag 77 / 80)
        // 77 len  9F27 01 <CID>  9F36 02 <ATC>  9F26 08 <AC>
        return new byte[] {
            0x77,                         // Response Message Template Format 2 (tag 77)
            0x0F,                         // length
            TAG_CID, TAG_CID_LOW, 0x01,  // CID tag + len
                0x40,                     // TC (Transaction Certificate)
            TAG_ATC_HIGH, TAG_ATC_LOW, 0x02,  // ATC tag + len
                atc[0], atc[1],
            TAG_AC_HIGH, TAG_AC_LOW, 0x08,    // AC tag + len
                // Placeholder AC – a real implementation would compute this
                // using 3DES or AES with the issuer application keys.
                (byte) 0xDE, (byte) 0xAD,
                (byte) 0xBE, (byte) 0xEF,
                0x00, 0x00, 0x00, 0x00
        };
    }

    /* ------------------------------------------------------------------ */
    /*  GET DATA                                                            */
    /* ------------------------------------------------------------------ */

    private void processGetData(APDU apdu) {
        byte[] buf  = apdu.getBuffer();
        byte tagHigh = buf[OFFSET_P1];
        byte tagLow  = buf[OFFSET_P2];

        if (tagHigh == TAG_ATC_HIGH && tagLow == TAG_ATC_LOW) {
            // Return Application Transaction Counter
            byte[] resp = { TAG_ATC_HIGH, TAG_ATC_LOW, 0x02, atc[0], atc[1] };
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) resp.length);
            apdu.sendBytesLong(resp, (short) 0, (short) resp.length);
        } else {
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }
    }

    /* ------------------------------------------------------------------ */
    /*  Helpers                                                             */
    /* ------------------------------------------------------------------ */

    /** Increment the big-endian 2-byte ATC. */
    private void incrementATC() {
        short val = Util.makeShort(atc[0], atc[1]);
        val++;
        Util.setShort(atc, (short) 0, val);
    }
}
