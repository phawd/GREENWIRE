package com.greenwire.hce;

import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.util.Arrays;
import java.util.Locale;

/**
 * TransitHCEService — transit card emulation HCE service.
 *
 * <p>Emulates common transit smart card protocols over ISO 14443-4 (IsoDep),
 * covering the following transit systems:
 * <ul>
 *   <li><b>Oyster</b> — Transport for London (TfL); ITSO EN 15320 compliant.
 *       AID: {@code A0000000428001}</li>
 *   <li><b>Suica / PASMO</b> — JR East Japan; FeliCa-derived over ISO 14443.
 *       AID: {@code A0000003180000}</li>
 *   <li><b>Clipper</b> — Bay Area (BART/Muni).
 *       AID: {@code A0000001032010}</li>
 *   <li><b>ORCA</b> — Seattle / Puget Sound.
 *       AID: {@code A0000004040000}</li>
 *   <li><b>Opal</b> — Transport for NSW, Australia.
 *       AID: {@code A0000005035010}</li>
 *   <li><b>ITSO Generic</b> — UK rail / national bus.
 *       AID: {@code A0000000860001}</li>
 * </ul>
 *
 * <p>Each emulated card provides:
 * <ul>
 *   <li>A configurable card serial number (card ID)</li>
 *   <li>A simulated balance (default: £/$/¥ 20.00 in minor units)</li>
 *   <li>A synthetic journey history (last 5 trips)</li>
 * </ul>
 *
 * <p>If the GREENWIRE relay is connected, all APDUs are forwarded to the host
 * for full protocol fidelity.
 *
 * <p>Spec ref:
 * <ul>
 *   <li>ITSO EN 15320 Parts 1–6 (UK interoperable ticketing)</li>
 *   <li>ISO/IEC 7816-4 (APDU structure)</li>
 *   <li>ISO/IEC 14443 Parts 1–4 (contactless proximity)</li>
 *   <li>JIS X 6319-4 (FeliCa — Suica/PASMO base)</li>
 * </ul>
 */
public class TransitHCEService extends HostApduService {

    private static final String TAG = "GW-Transit";

    // ── SharedPreferences keys ────────────────────────────────────────────
    private static final String PREFS_NAME      = "gw_prefs";
    private static final String KEY_TRANSIT_ID  = "transit_card_id";
    private static final String KEY_BALANCE      = "transit_balance";  // minor units

    // ── Defaults ──────────────────────────────────────────────────────────
    /** Default Oyster-style card serial number (10 decimal digits). */
    private static final String DEFAULT_CARD_ID = "1234567890";
    /** Default balance in minor units (2000 = £20.00 / $20.00). */
    private static final int    DEFAULT_BALANCE = 2000;

    // ── Status words ──────────────────────────────────────────────────────
    private static final byte[] SW_9000 = { (byte)0x90, 0x00 };
    private static final byte[] SW_6A82 = { 0x6A, (byte)0x82 };
    private static final byte[] SW_6985 = { 0x69, (byte)0x85 };
    private static final byte[] SW_6D00 = { 0x6D, 0x00 };

    // ── Known transit AIDs (hex strings, uppercase) ───────────────────────
    private static final String AID_OYSTER  = "A0000000428001";
    private static final String AID_SUICA   = "A0000003180000";
    private static final String AID_CLIPPER = "A0000001032010";
    private static final String AID_ORCA    = "A0000004040000";
    private static final String AID_OPAL    = "A0000005035010";
    private static final String AID_ITSO    = "A0000000860001";

    // ── State ─────────────────────────────────────────────────────────────
    private NFCLogger         mLogger;
    private NFCRelaySocket    mRelay;
    private SharedPreferences mPrefs;
    /** AID selected in the most recent SELECT command. */
    private String            mSelectedAid = "";

    // ── HostApduService lifecycle ─────────────────────────────────────────

    @Override
    public void onCreate() {
        super.onCreate();
        mLogger = GreenwireApp.get().getLogger();
        mRelay  = GreenwireApp.get().getRelay();
        mPrefs  = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        Log.i(TAG, "Transit HCE service created");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "Transit HCE service destroyed");
    }

    // ── APDU processing ───────────────────────────────────────────────────

    /**
     * Process an APDU from the transit gate reader.
     * Relay-first; fallback to simulated balance/journey responses.
     *
     * <p>Spec ref: ITSO EN 15320-1 § 5 (APDU command structure)
     *
     * @param apdu   raw APDU bytes from the gate reader
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
     * Provide simulated transit card responses when relay is unavailable.
     * Handles SELECT, GET DATA (balance query), and READ RECORD (journey history).
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

        // GET DATA (INS=CA) — ITSO/Oyster balance enquiry
        // CLA=80 INS=CA P1=00 P2=01 = Get Balance (custom)
        if (ins == (byte)0xCA) {
            return buildBalanceResponse();
        }

        // READ RECORD (INS=B2) — journey history records
        if (ins == (byte)0xB2) {
            return buildJourneyRecordResponse(apdu[2], apdu[3]);
        }

        // VERIFY (INS=20) — some transit systems use PIN verify
        if (ins == 0x20) {
            return SW_9000; // Accept any PIN (lab mode)
        }

        // GET CHALLENGE (INS=84) — random challenge for dynamic auth
        if (ins == (byte)0x84) {
            return buildChallengeResponse();
        }

        return SW_6D00;
    }

    /**
     * Handle SELECT by DF Name — match against known transit AIDs.
     *
     * @param apdu SELECT APDU bytes
     * @return FCI response for the selected AID, or 6A82
     */
    private byte[] handleSelect(byte[] apdu) {
        if (apdu.length < 5) return SW_6A82;
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return SW_6A82;

        byte[] aid = Arrays.copyOfRange(apdu, 5, 5 + lc);
        mSelectedAid = NFCLogger.bytesToHex(aid).toUpperCase(Locale.US);
        Log.d(TAG, "Transit SELECT AID: " + mSelectedAid);

        switch (mSelectedAid) {
            case AID_OYSTER:  return buildOysterFci();
            case AID_SUICA:   return buildSuicaFci();
            case AID_CLIPPER: return buildGenericTransitFci("Clipper",  AID_CLIPPER);
            case AID_ORCA:    return buildGenericTransitFci("ORCA",     AID_ORCA);
            case AID_OPAL:    return buildGenericTransitFci("Opal",     AID_OPAL);
            case AID_ITSO:    return buildGenericTransitFci("ITSO",     AID_ITSO);
            default:          return SW_6A82;
        }
    }

    /**
     * Oyster Card FCI response.
     * Oyster uses a proprietary ITSO-based AID structure over ISO 14443-4.
     * Spec ref: TfL Oyster System Specification (public NDA-free portions)
     *           ITSO EN 15320-3 (Card Application)
     *
     * @return Oyster FCI (6F template) + 9000
     */
    private byte[] buildOysterFci() {
        String cardId = mPrefs.getString(KEY_TRANSIT_ID, DEFAULT_CARD_ID);
        byte[] cardIdBytes = cardId.getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        // Build FCI: 6F template + 84 (AID) + A5 (proprietary: card serial in 9F7F)
        byte aidLen  = 0x07;
        byte[] aidBytes = NFCLogger.hexToBytes(AID_OYSTER);
        byte propLen = (byte)(2 + cardIdBytes.length);
        byte fciLen  = (byte)(2 + aidLen + 2 + propLen);

        byte[] fci = new byte[2 + fciLen + 2];
        int off = 0;
        fci[off++] = 0x6F; fci[off++] = fciLen;
        fci[off++] = (byte)0x84; fci[off++] = aidLen;
        System.arraycopy(aidBytes, 0, fci, off, aidLen); off += aidLen;
        fci[off++] = (byte)0xA5; fci[off++] = propLen;
        fci[off++] = (byte)0x9F; // Oyster custom: card serial tag
        fci[off++] = (byte)cardIdBytes.length;
        System.arraycopy(cardIdBytes, 0, fci, off, cardIdBytes.length); off += cardIdBytes.length;
        fci[off++] = (byte)0x90; fci[off] = 0x00;
        return fci;
    }

    /**
     * Suica / PASMO FCI response.
     * Suica runs over FeliCa / ISO 14443-A but also has an ISO 14443-4 layer.
     * Spec ref: JR East Suica System Technical Specification (public sections)
     *           JIS X 6319-4 (FeliCa)
     *
     * @return Suica FCI + 9000
     */
    private byte[] buildSuicaFci() {
        return buildGenericTransitFci("Suica", AID_SUICA);
    }

    /**
     * Build a generic transit card FCI response using the supplied label and AID.
     *
     * @param label  printable ASCII label (up to 16 chars)
     * @param aidHex AID as an uppercase hex string
     * @return 6F FCI template bytes + 9000
     */
    private byte[] buildGenericTransitFci(String label, String aidHex) {
        byte[] aidBytes   = NFCLogger.hexToBytes(aidHex);
        byte[] labelBytes = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        byte aidLen   = (byte) aidBytes.length;
        byte labelLen = (byte) labelBytes.length;
        byte propLen  = (byte)(2 + labelLen); // A5 contains 50 <label>
        byte fciLen   = (byte)(2 + aidLen + 2 + propLen);

        byte[] fci = new byte[2 + fciLen + 2];
        int off = 0;
        fci[off++] = 0x6F; fci[off++] = fciLen;
        fci[off++] = (byte)0x84; fci[off++] = aidLen;
        System.arraycopy(aidBytes, 0, fci, off, aidLen); off += aidLen;
        fci[off++] = (byte)0xA5; fci[off++] = propLen;
        fci[off++] = 0x50; fci[off++] = labelLen;  // Application Label
        System.arraycopy(labelBytes, 0, fci, off, labelLen); off += labelLen;
        fci[off++] = (byte)0x90; fci[off] = 0x00;
        return fci;
    }

    /**
     * Return a balance response in a simple proprietary TLV format.
     * Tags:
     * <ul>
     *   <li>9F 4F 04 — Balance (4 bytes, big-endian, minor units)</li>
     * </ul>
     *
     * <p>The balance value is read from SharedPreferences (key: transit_balance).
     *
     * @return balance data + 9000
     */
    private byte[] buildBalanceResponse() {
        int balance = mPrefs.getInt(KEY_BALANCE, DEFAULT_BALANCE);
        return new byte[]{
            // 9F 4F 04 — Balance tag (proprietary transit tag)
            (byte)0x9F, 0x4F, 0x04,
              (byte)((balance >> 24) & 0xFF),
              (byte)((balance >> 16) & 0xFF),
              (byte)((balance >>  8) & 0xFF),
              (byte)( balance        & 0xFF),
            // SW: 90 00
            (byte)0x90, 0x00
        };
    }

    /**
     * Build a synthetic journey history record.
     * Returns a minimal record template (70) with:
     * <ul>
     *   <li>9F 70 — Entry station code</li>
     *   <li>9F 71 — Exit station code (00 00 = not yet tapped out)</li>
     *   <li>9F 72 — Journey date (YYMMDD packed BCD)</li>
     *   <li>9F 73 — Fare deducted (minor units, 2 bytes)</li>
     * </ul>
     *
     * <p>Spec ref: ITSO EN 15320-3 § 8 (Journey Data)
     *
     * @param p1 record number (1–5: return dummy records; else 6A83)
     * @param p2 SFI
     * @return journey record bytes + 9000, or 6A83
     */
    private byte[] buildJourneyRecordResponse(byte p1, byte p2) {
        int recNum = p1 & 0xFF;
        if (recNum < 1 || recNum > 5) {
            return new byte[]{0x6A, (byte)0x83}; // Record not found
        }

        // Synthetic entry/exit station codes (0x01xx–0x05xx) and fares
        int entry = 0x0100 + recNum;
        int exit  = 0x0200 + recNum;
        int fare  = 150 + (recNum * 30); // 180–300 minor units

        return new byte[]{
            // 70 14 — Record Template
            0x70, 0x14,
              // 9F 70 02 — Entry station
              (byte)0x9F, 0x70, 0x02, (byte)(entry >> 8), (byte)(entry & 0xFF),
              // 9F 71 02 — Exit station
              (byte)0x9F, 0x71, 0x02, (byte)(exit  >> 8), (byte)(exit  & 0xFF),
              // 9F 72 03 — Date: 24 01 15 (YY MM DD = 2024-01-15, packed BCD)
              (byte)0x9F, 0x72, 0x03, 0x24, 0x01, (byte)(0x10 + recNum),
              // 9F 73 02 — Fare deducted
              (byte)0x9F, 0x73, 0x02, (byte)(fare >> 8), (byte)(fare & 0xFF),
            // SW: 90 00
            (byte)0x90, 0x00
        };
    }

    /**
     * Return a 4-byte random challenge for dynamic authentication.
     * Spec ref: ISO 7816-4 § 7.5.3 (GET CHALLENGE)
     *
     * @return 4-byte challenge + 9000
     */
    private byte[] buildChallengeResponse() {
        byte[] challenge = new byte[4];
        new java.util.Random().nextBytes(challenge);
        return new byte[]{
            challenge[0], challenge[1], challenge[2], challenge[3],
            (byte)0x90, 0x00
        };
    }
}
