package com.greenwire.hce;

import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.util.Arrays;
import java.util.Locale;

/**
 * AccessCardHCEService — physical access card emulation HCE service.
 *
 * <p>Emulates several classes of physical access control smart cards using the
 * ISO 14443-4 transport layer available via Android's HCE (Host Card Emulation):
 * <ul>
 *   <li><b>HID iCLASS</b>  — ISO 14443-4 layer over HID Global smart card platform.
 *       AID: {@code A0000003971002}</li>
 *   <li><b>HID Prox (lab)</b> — Simulated 125 kHz EM4100/HID26-bit format
 *       delivered over ISO 14443-4.  AID: {@code A000000620}</li>
 *   <li><b>MIFARE DESFire PACS</b> — DESFire EV1 application for building access.
 *       AID: {@code A0000008471100}</li>
 *   <li><b>Gallagher T11</b> — Gallagher Security access control.
 *       AID: {@code A0000005272101}</li>
 *   <li><b>Generic PACS</b> — Catch-all AID for unrecognised access readers.
 *       AID: {@code A000000092}</li>
 * </ul>
 *
 * <h3>Configuration</h3>
 * Facility code and card number are stored in SharedPreferences and can be
 * set from {@link MainActivity}'s settings panel:
 * <pre>
 *   gw_prefs / access_facility_code  (int, default 1)
 *   gw_prefs / access_card_number    (int, default 1001)
 * </pre>
 *
 * <h3>Response format</h3>
 * When a reader sends a GET DATA / READ command, the service returns the
 * Wiegand 26-bit bitstream encoded as the two's-complement of the
 * facility+card payload:
 * <pre>
 *   Bits: P(1) FC(8) CN(16) P(1) = 26 bits = 4 bytes (zero-padded)
 * </pre>
 *
 * <p>Spec ref:
 * <ul>
 *   <li>ISO/IEC 14443 Parts 1–4 (contactless smart card protocol)</li>
 *   <li>HID Global iCLASS Specification Rev 5.0</li>
 *   <li>Wiegand Interface Protocol (26-bit standard format)</li>
 *   <li>IEC 62056-21 (access card data encoding)</li>
 * </ul>
 */
public class AccessCardHCEService extends HostApduService {

    private static final String TAG = "GW-Access";

    // ── SharedPreferences keys ────────────────────────────────────────────
    private static final String PREFS_NAME    = "gw_prefs";
    private static final String KEY_FACILITY  = "access_facility_code";
    private static final String KEY_CARD_NUM  = "access_card_number";

    /** Default facility code — single-digit for lab testing. */
    private static final int DEFAULT_FACILITY = 1;
    /** Default card number within the facility. */
    private static final int DEFAULT_CARD_NUM = 1001;

    // ── Status words ──────────────────────────────────────────────────────
    private static final byte[] SW_9000 = { (byte)0x90, 0x00 };
    private static final byte[] SW_6A82 = { 0x6A, (byte)0x82 };
    private static final byte[] SW_6985 = { 0x69, (byte)0x85 };
    private static final byte[] SW_6D00 = { 0x6D, 0x00 };

    // ── Known AIDs ────────────────────────────────────────────────────────
    private static final String AID_HID_ICLASS    = "A0000003971002";
    private static final String AID_HID_PROX      = "A000000620";
    private static final String AID_DESFIRE_PACS  = "A0000008471100";
    private static final String AID_GALLAGHER      = "A0000005272101";
    private static final String AID_GENERIC_PACS  = "A000000092";

    // ── State ─────────────────────────────────────────────────────────────
    private NFCLogger         mLogger;
    private NFCRelaySocket    mRelay;
    private SharedPreferences mPrefs;
    private String            mSelectedAid = "";

    // ── HostApduService lifecycle ─────────────────────────────────────────

    @Override
    public void onCreate() {
        super.onCreate();
        mLogger = GreenwireApp.get().getLogger();
        mRelay  = GreenwireApp.get().getRelay();
        mPrefs  = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        Log.i(TAG, "Access card HCE service created");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "Access card HCE service destroyed");
    }

    // ── APDU processing ───────────────────────────────────────────────────

    /**
     * Process APDU from an access control reader.
     * Relays to GREENWIRE Python host if connected; otherwise serves locally.
     *
     * <p>Spec ref: ISO/IEC 14443-4 § 7 (APDU transport protocol T=CL)
     *
     * @param apdu   raw APDU bytes from the access reader
     * @param extras framework extras
     * @return APDU response bytes
     */
    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        if (apdu == null || apdu.length < 4) {
            return SW_6985;
        }

        long startMs = System.currentTimeMillis();
        String hexIn = NFCLogger.bytesToHex(apdu);
        Log.d(TAG, "APDU ← " + hexIn);
        mLogger.logCommand(apdu);

        byte[] response = null;
        if (mRelay.isConnected()) {
            String respHex = mRelay.relayApdu(hexIn);
            if (respHex != null) response = NFCLogger.hexToBytes(respHex);
        }

        if (response == null) {
            response = localFallback(apdu);
        }

        long elapsed = System.currentTimeMillis() - startMs;
        mLogger.logResponse(apdu, response, elapsed);
        Log.d(TAG, "APDU → " + NFCLogger.bytesToHex(response));
        return response;
    }

    @Override
    public void onDeactivated(int reason) {
        Log.i(TAG, "Deactivated reason=" + reason);
        mSelectedAid = "";
    }

    // ── Local fallback ────────────────────────────────────────────────────

    /**
     * Simulate access card responses for the selected AID.
     *
     * @param apdu APDU command bytes
     * @return locally-computed response
     */
    private byte[] localFallback(byte[] apdu) {
        byte ins = apdu[1];
        byte p1  = apdu[2];

        // SELECT by DF Name
        if (ins == (byte)0xA4 && p1 == 0x04) {
            return handleSelect(apdu);
        }

        // GET DATA (INS=CA) — read card identity data
        if (ins == (byte)0xCA) {
            return buildCardDataResponse();
        }

        // VERIFY (INS=20) — PIN/passcode verify (accept all in lab mode)
        if (ins == 0x20) {
            return SW_9000;
        }

        // AUTHENTICATE / GET CHALLENGE (INS=84)
        if (ins == (byte)0x84) {
            return buildChallengeResponse();
        }

        // INTERNAL AUTHENTICATE (INS=88) — used by iCLASS readers
        if (ins == (byte)0x88) {
            return buildInternalAuthResponse(apdu);
        }

        // READ BINARY (INS=B0) — raw byte read from access card files
        if (ins == (byte)0xB0) {
            return buildReadBinaryResponse(apdu);
        }

        return SW_6D00;
    }

    /**
     * Handle SELECT by DF Name.  Stores the selected AID for subsequent commands.
     *
     * @param apdu SELECT APDU bytes
     * @return FCI response or 6A82
     */
    private byte[] handleSelect(byte[] apdu) {
        if (apdu.length < 5) return SW_6A82;
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return SW_6A82;

        byte[] aid = Arrays.copyOfRange(apdu, 5, 5 + lc);
        mSelectedAid = NFCLogger.bytesToHex(aid).toUpperCase(Locale.US);
        Log.d(TAG, "Access SELECT AID: " + mSelectedAid);

        switch (mSelectedAid) {
            case AID_HID_ICLASS:
                return buildHidIclassFci();
            case AID_HID_PROX:
            case AID_DESFIRE_PACS:
            case AID_GALLAGHER:
            case AID_GENERIC_PACS:
                return buildGenericPacsFci(mSelectedAid);
            default:
                return SW_6A82;
        }
    }

    /**
     * Build an HID iCLASS FCI response.
     *
     * <p>iCLASS uses a proprietary application structure over ISO 14443-4.
     * The FCI includes a credential type byte (0x02 = iCLASS standard).
     *
     * <p>Spec ref: HID Global iCLASS Specification Rev 5.0 § 4 (Application Select)
     *
     * @return FCI (6F) + 9000
     */
    private byte[] buildHidIclassFci() {
        byte[] aidBytes = NFCLogger.hexToBytes(AID_HID_ICLASS);
        return buildFci(aidBytes, "iCLASS", new byte[]{0x02}); // 0x02 = iCLASS credential type
    }

    /**
     * Build a generic Physical Access Control System FCI.
     *
     * @param aidHex AID as hex string
     * @return FCI (6F) + 9000
     */
    private byte[] buildGenericPacsFci(String aidHex) {
        byte[] aidBytes = NFCLogger.hexToBytes(aidHex);
        return buildFci(aidBytes, "PACS", null);
    }

    /**
     * Build a 6F FCI template given an AID, optional label, and optional proprietary data.
     *
     * @param aid   AID bytes
     * @param label ASCII label (may be null)
     * @param extra extra proprietary bytes appended in A5 tag (may be null)
     * @return FCI bytes + 9000
     */
    private byte[] buildFci(byte[] aid, String label, byte[] extra) {
        byte[] labelBytes = (label != null)
                ? label.getBytes(java.nio.charset.StandardCharsets.US_ASCII)
                : new byte[0];
        byte[] extraBytes = (extra != null) ? extra : new byte[0];

        int propLen = (labelBytes.length > 0 ? 2 + labelBytes.length : 0)
                    + (extraBytes.length > 0 ? 2 + extraBytes.length : 0);
        int fciLen  = 2 + aid.length + (propLen > 0 ? 2 + propLen : 0);

        byte[] fci = new byte[2 + fciLen + 2];
        int off = 0;
        fci[off++] = 0x6F; fci[off++] = (byte) fciLen;
        fci[off++] = (byte)0x84; fci[off++] = (byte) aid.length;
        System.arraycopy(aid, 0, fci, off, aid.length); off += aid.length;

        if (propLen > 0) {
            fci[off++] = (byte)0xA5; fci[off++] = (byte) propLen;
            if (labelBytes.length > 0) {
                fci[off++] = 0x50; fci[off++] = (byte) labelBytes.length;
                System.arraycopy(labelBytes, 0, fci, off, labelBytes.length); off += labelBytes.length;
            }
            if (extraBytes.length > 0) {
                fci[off++] = (byte)0x9F; fci[off++] = (byte) extraBytes.length;
                System.arraycopy(extraBytes, 0, fci, off, extraBytes.length); off += extraBytes.length;
            }
        }
        fci[off++] = (byte)0x90; fci[off] = 0x00;
        return fci;
    }

    /**
     * Return the card identity data containing the Wiegand 26-bit payload.
     *
     * <p>Wiegand 26-bit format (standard HID format):
     * <pre>
     * Bit  0:    Even parity over bits 1–12
     * Bits 1–8:  Facility Code (8 bits)
     * Bits 9–24: Card Number (16 bits)
     * Bit 25:    Odd parity over bits 13–24
     * Total: 26 bits → packed as 4 bytes (upper 6 bits = 0)
     * </pre>
     *
     * <p>Spec ref: HID Wiegand 26-bit Open Format Card Specification
     *
     * @return card data TLV (9F 60 04 <wiegand_bytes>) + 9000
     */
    private byte[] buildCardDataResponse() {
        int facilityCode = mPrefs.getInt(KEY_FACILITY, DEFAULT_FACILITY);
        int cardNumber   = mPrefs.getInt(KEY_CARD_NUM, DEFAULT_CARD_NUM);

        // Build 26-bit Wiegand payload as 32-bit integer (upper 6 bits unused)
        int payload = buildWiegand26(facilityCode & 0xFF, cardNumber & 0xFFFF);

        return new byte[]{
            // 9F 60 04 — Card Identity (proprietary PACS tag 9F60)
            (byte)0x9F, 0x60, 0x04,
              (byte)((payload >> 24) & 0xFF),
              (byte)((payload >> 16) & 0xFF),
              (byte)((payload >>  8) & 0xFF),
              (byte)( payload        & 0xFF),
            // SW: 90 00
            (byte)0x90, 0x00
        };
    }

    /**
     * Build a Wiegand 26-bit value from facility code and card number.
     *
     * <p>Parity calculation:
     * <ul>
     *   <li>Even parity bit (bit 25, MSB of result): over bits 24–13 (FC[7:0], CN[15:8])</li>
     *   <li>Odd parity bit  (bit  0, LSB of result): over bits 12–1  (CN[7:0])</li>
     * </ul>
     *
     * @param fc  8-bit facility code
     * @param cn  16-bit card number
     * @return 26-bit Wiegand value stored in a 32-bit int (upper 6 bits = 0)
     */
    private static int buildWiegand26(int fc, int cn) {
        // Pack raw 24 bits: FC(8) | CN(16)
        int raw = ((fc & 0xFF) << 16) | (cn & 0xFFFF);

        // Even parity bit: bits [23:12] of raw (i.e. FC[7:0], CN[15:8])
        int evenGroup = (raw >> 12) & 0xFFF;
        int evenParity = Integer.bitCount(evenGroup) & 1; // 0 if already even

        // Odd parity bit: bits [11:0] of raw (i.e. CN[7:0])
        int oddGroup = raw & 0xFFF;
        int oddParity = (~Integer.bitCount(oddGroup)) & 1; // 1 if already even (make odd)

        // Final 26-bit layout: evenParity(1) + FC(8) + CN(16) + oddParity(1)
        return (evenParity << 25) | (raw << 1) | oddParity;
    }

    /**
     * Return a 4-byte random challenge for the INTERNAL AUTHENTICATE flow.
     * Spec ref: ISO/IEC 7816-4 § 7.5.3 (GET CHALLENGE)
     *
     * @return 4-byte random challenge + 9000
     */
    private byte[] buildChallengeResponse() {
        byte[] challenge = new byte[4];
        new java.util.Random().nextBytes(challenge);
        return new byte[]{
            challenge[0], challenge[1], challenge[2], challenge[3],
            (byte)0x90, 0x00
        };
    }

    /**
     * INTERNAL AUTHENTICATE response — XOR of the challenge with card data.
     * This is a simplified non-cryptographic response for lab testing.
     *
     * <p>Spec ref: ISO/IEC 7816-4 § 7.5.3 (INTERNAL AUTHENTICATE)
     *             HID iCLASS Specification § 5 (Mutual Authentication)
     *
     * @param apdu the INTERNAL AUTHENTICATE APDU
     * @return 8-byte response token + 9000
     */
    private byte[] buildInternalAuthResponse(byte[] apdu) {
        int facilityCode = mPrefs.getInt(KEY_FACILITY, DEFAULT_FACILITY);
        int cardNumber   = mPrefs.getInt(KEY_CARD_NUM, DEFAULT_CARD_NUM);

        // Extract challenge from APDU data field
        byte[] challenge = new byte[8];
        if (apdu.length >= 5) {
            int lc = apdu[4] & 0xFF;
            int copyLen = Math.min(lc, Math.min(8, apdu.length - 5));
            System.arraycopy(apdu, 5, challenge, 0, copyLen);
        }

        // Build a simple response token (non-cryptographic, lab use)
        // Response = challenge XOR {0,0,FC,FC,CN>>8,CN&FF,0,0}
        byte[] token = new byte[8];
        token[0] = (byte)(challenge[0] ^ 0x00);
        token[1] = (byte)(challenge[1] ^ 0x00);
        token[2] = (byte)(challenge[2] ^ (facilityCode & 0xFF));
        token[3] = (byte)(challenge[3] ^ (facilityCode & 0xFF));
        token[4] = (byte)(challenge[4] ^ ((cardNumber >> 8) & 0xFF));
        token[5] = (byte)(challenge[5] ^ (cardNumber & 0xFF));
        token[6] = (byte)(challenge[6] ^ 0x00);
        token[7] = (byte)(challenge[7] ^ 0x00);

        return new byte[]{
            token[0], token[1], token[2], token[3],
            token[4], token[5], token[6], token[7],
            (byte)0x90, 0x00
        };
    }

    /**
     * READ BINARY response — return the Wiegand card data at the requested offset.
     *
     * <p>Spec ref: ISO/IEC 7816-4 § 7.2.3 (READ BINARY)
     *
     * @param apdu READ BINARY APDU
     * @return binary data bytes + 9000
     */
    private byte[] buildReadBinaryResponse(byte[] apdu) {
        int facilityCode = mPrefs.getInt(KEY_FACILITY, DEFAULT_FACILITY);
        int cardNumber   = mPrefs.getInt(KEY_CARD_NUM, DEFAULT_CARD_NUM);
        int wiegand      = buildWiegand26(facilityCode & 0xFF, cardNumber & 0xFFFF);

        // Return 8 bytes: 4 zero padding + 4 Wiegand bytes
        return new byte[]{
            0x00, 0x00, 0x00, 0x00,
            (byte)((wiegand >> 24) & 0xFF),
            (byte)((wiegand >> 16) & 0xFF),
            (byte)((wiegand >>  8) & 0xFF),
            (byte)( wiegand        & 0xFF),
            (byte)0x90, 0x00
        };
    }
}
