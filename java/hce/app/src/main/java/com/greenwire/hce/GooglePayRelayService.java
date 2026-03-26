package com.greenwire.hce;

import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.util.Arrays;
import java.util.Locale;

/**
 * GooglePayRelayService — Google Pay / VTS / MDES token replay HCE service.
 *
 * <p>This service emulates the NFC payment behaviour of Google Pay on Android
 * using either:
 * <ol>
 *   <li><b>Relay mode</b>: Forwards every APDU to the GREENWIRE Python host
 *       which performs or intercepts the actual token exchange.</li>
 *   <li><b>Stored token mode</b>: Responds from locally-stored DPAN, expiry and
 *       service code — useful for token replay and regression testing.</li>
 * </ol>
 *
 * <p>AIDs handled (see {@code res/xml/apduservice_googlepay.xml}):
 * <ul>
 *   <li>{@code 325041592E5359532E4444463031} — PPSE</li>
 *   <li>{@code A000000004101000} — Google Pay wallet AID (Android/Visa registered)</li>
 * </ul>
 *
 * <p>Supported EMV commands:
 * <ul>
 *   <li>SELECT PPSE (INS=A4, AID=PPSE)</li>
 *   <li>SELECT AID (INS=A4, AID=A000000004101000)</li>
 *   <li>GET PROCESSING OPTIONS (CLA=80 INS=A8)</li>
 *   <li>READ RECORD (INS=B2)</li>
 *   <li>GENERATE AC (CLA=80 INS=AE) — returns ARQC with stored token data</li>
 *   <li>COMPUTE CRYPTOGRAPHIC CHECKSUM (CLA=80 INS=2A) — Visa payWave specific</li>
 * </ul>
 *
 * <p>Spec ref:
 * <ul>
 *   <li>Visa Token Service (VTS) Tokenization Specification v2.3</li>
 *   <li>Mastercard MDES Digital Enablement Service Specification</li>
 *   <li>EMVCo Contactless Specifications Book C-2 v2.10</li>
 *   <li>ISO/IEC 7816-4 (APDU structure)</li>
 * </ul>
 */
public class GooglePayRelayService extends HostApduService {

    private static final String TAG = "GW-GPay";

    // ── SharedPreferences keys ────────────────────────────────────────────
    private static final String PREFS_NAME    = "gw_prefs";
    private static final String KEY_GPAY_DPAN = "gpay_dpan";
    private static final String KEY_GPAY_EXP  = "gpay_expiry";  // YYMM
    private static final String KEY_GPAY_SVC  = "gpay_svc_code";
    private static final String KEY_ATC       = "atc";

    /** Default VTS test token PAN. */
    private static final String DEFAULT_DPAN     = "4900000000000086";
    private static final String DEFAULT_EXPIRY   = "2612"; // YYMM
    private static final String DEFAULT_SVC_CODE = "101";

    // ── Status words ──────────────────────────────────────────────────────
    private static final byte[] SW_9000 = { (byte)0x90, 0x00 };
    private static final byte[] SW_6985 = { 0x69, (byte)0x85 };
    private static final byte[] SW_6A82 = { 0x6A, (byte)0x82 };
    private static final byte[] SW_6D00 = { 0x6D, 0x00 };

    // ── PPSE response listing the Google Pay AID ──────────────────────────
    /**
     * PPSE FCI response advertising the Google Pay wallet AID A000000004101000.
     *
     * <p>Structure:
     * <pre>
     * 6F xx   — FCI Template
     *   84 0E  — DF Name: 2PAY.SYS.DDF01
     *   A5 xx  — FCI Proprietary Template
     *     BF 0C xx — FCI Issuer Discretionary Data
     *       61 xx  — Application Template
     *         4F 08 A0 00 00 00 04 10 10 00  — Google Pay wallet AID
     *         50 0A 476F6F676C65205061790000 — "Google Pay"
     *         87 01 01                        — Priority 1
     * 90 00
     * </pre>
     *
     * Spec ref: EMVCo Book B § 3.2 (SELECT PPSE response)
     */
    private static final byte[] GPAY_PPSE_RESPONSE = {
        // 6F 36 — FCI Template
        0x6F, 0x36,
          // 84 0E — DF Name: "2PAY.SYS.DDF01"
          (byte)0x84, 0x0E,
            0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31,
          // A5 24 — FCI Proprietary Template
          (byte)0xA5, 0x24,
            // BF 0C 21 — FCI Issuer Discretionary Data
            (byte)0xBF, 0x0C, 0x21,
              // 61 1F — Application Template (Google Pay)
              0x61, 0x1F,
                // 4F 08 — AID: A000000004101000 (Google Pay wallet AID)
                0x4F, 0x08, (byte)0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x00,
                // 50 0A — Application Label: "Google Pay"
                0x50, 0x0A, 0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x20, 0x50, 0x61, 0x79,
                // 87 01 01 — Priority indicator 1
                (byte)0x87, 0x01, 0x01,
        // SW: 90 00
        (byte)0x90, 0x00
    };

    // ── Google Pay FCI (SELECT AID response) ─────────────────────────────
    /**
     * FCI response for SELECT A000000004101000.
     *
     * <p>Includes PDOL requesting transaction amount, currency, terminal
     * verification results — all standard EMVCo requirements.
     *
     * <p>Spec ref: EMVCo Book C-2 § 3.3 (application selection)
     */
    private static final byte[] GPAY_FCI_RESPONSE = {
        // 6F 2A — FCI Template
        0x6F, 0x2A,
          // 84 08 — DF Name: A000000004101000
          (byte)0x84, 0x08, (byte)0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x00,
          // A5 1E — FCI Proprietary Template
          (byte)0xA5, 0x1E,
            // 50 0A — Application Label: "Google Pay"
            0x50, 0x0A, 0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x20, 0x50, 0x61, 0x79,
            // 5F 2D 02 — Language Preference: "en"
            0x5F, 0x2D, 0x02, 0x65, 0x6E,
            // 9F 38 06 — PDOL: amount (6) + terminal country (2) — minimal PDOL
            (byte)0x9F, 0x38, 0x06,
              (byte)0x9F, 0x02, 0x06, // 9F02: Amount Authorised (6 bytes)
              (byte)0x9F, 0x1A, 0x02, // 9F1A: Terminal Country Code (2 bytes)
        // SW: 90 00
        (byte)0x90, 0x00
    };

    // ── Service state ─────────────────────────────────────────────────────
    private NFCLogger         mLogger;
    private NFCRelaySocket    mRelay;
    private SharedPreferences mPrefs;

    // ── HostApduService lifecycle ─────────────────────────────────────────

    @Override
    public void onCreate() {
        super.onCreate();
        mLogger = GreenwireApp.get().getLogger();
        mRelay  = GreenwireApp.get().getRelay();
        mPrefs  = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        Log.i(TAG, "Google Pay relay HCE service created");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "Google Pay relay HCE service destroyed");
    }

    // ── APDU processing ───────────────────────────────────────────────────

    /**
     * Process each APDU from the contactless reader.
     * Relay-first: if GREENWIRE relay is available, all APDUs are forwarded.
     * Fallback: locally construct EMV responses using stored DPAN/expiry.
     *
     * <p>Spec ref: EMVCo Book C-2 § 3 (transaction flow)
     *
     * @param apdu   raw APDU bytes from reader
     * @param extras framework extras (unused)
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

        // Try relay first
        byte[] response = null;
        if (mRelay.isConnected()) {
            String respHex = mRelay.relayApdu(hexIn);
            if (respHex != null) {
                response = NFCLogger.hexToBytes(respHex);
            }
        }

        if (response == null) {
            response = localFallback(apdu);
        }

        long elapsedMs = System.currentTimeMillis() - startMs;
        mLogger.logResponse(apdu, response, elapsedMs);

        // Track ATC for GENERATE AC
        if (apdu[1] == (byte)0xAE || (apdu[0] == (byte)0x80 && apdu[1] == (byte)0x2A)) {
            incrementAtc();
        }

        Log.d(TAG, "APDU → " + NFCLogger.bytesToHex(response));
        return response;
    }

    @Override
    public void onDeactivated(int reason) {
        Log.i(TAG, "Deactivated reason=" + reason);
    }

    // ── Local fallback (stored token mode) ────────────────────────────────

    /**
     * Generate a response from stored token data when relay is unavailable.
     * Covers the complete VTS contactless transaction flow.
     *
     * @param apdu APDU command bytes
     * @return locally-computed response
     */
    private byte[] localFallback(byte[] apdu) {
        byte cla = apdu[0];
        byte ins = apdu[1];
        byte p1  = apdu[2];

        // SELECT by DF Name (CLA=00 INS=A4 P1=04)
        if (ins == (byte)0xA4 && p1 == 0x04) {
            if (apdu.length < 5) return SW_6A82;
            int lc     = apdu[4] & 0xFF;
            if (apdu.length < 5 + lc) return SW_6A82;
            byte[] aid = Arrays.copyOfRange(apdu, 5, 5 + lc);
            String aidHex = NFCLogger.bytesToHex(aid).toUpperCase(Locale.US);

            // PPSE discovery
            if ("325041592E5359532E4444463031".equals(aidHex)) {
                return GPAY_PPSE_RESPONSE;
            }
            // Google Pay AID
            if (aidHex.startsWith("A000000004")) {
                return GPAY_FCI_RESPONSE;
            }
            return SW_6A82;
        }

        // GET PROCESSING OPTIONS (CLA=80 INS=A8) — EMVCo Book C-2 § 6.1
        if (cla == (byte)0x80 && ins == (byte)0xA8) {
            return buildGpoResponse();
        }

        // READ RECORD (INS=B2) — ISO 7816-4 § 7.3.3
        if (ins == (byte)0xB2) {
            return buildReadRecordResponse(apdu[2], apdu[3]);
        }

        // GENERATE AC (CLA=80 INS=AE) or COMPUTE CRYPTOGRAPHIC CHECKSUM (INS=2A)
        if (cla == (byte)0x80 && (ins == (byte)0xAE || ins == (byte)0x2A)) {
            return buildGenerateAcResponse();
        }

        return SW_6D00;
    }

    /**
     * GET PROCESSING OPTIONS response.
     * Returns AIP indicating SDA+DDA+CDA and AFL pointing to SFI 1, records 1–2.
     *
     * <p>Spec ref: EMVCo Book C-2 § 6.1.2 (VTS contactless GPO)
     *
     * @return GPO response template (80) + AIP + AFL + 9000
     */
    private byte[] buildGpoResponse() {
        return new byte[]{
            // 80 0A — Response Template Format 1
            (byte)0x80, 0x0A,
              // 82 02 — AIP: 5C 00 = SDA+DDA+CDA, no CVM (tap-and-go)
              (byte)0x82, 0x02, 0x5C, 0x00,
              // 94 04 — AFL: SFI=1, rec 1–2
              (byte)0x94, 0x04,
                0x08, 0x01, 0x02, 0x00,
            // SW: 90 00
            (byte)0x90, 0x00
        };
    }

    /**
     * READ RECORD response with Track 2 Equivalent Data and PAN Sequence Number.
     *
     * <p>The token PAN (DPAN) is stored in SharedPreferences as {@code gpay_dpan}.
     * Expiry is stored as YYMM in {@code gpay_expiry}.
     *
     * <p>Spec ref: VTS Tokenization Specification v2.3 § 4 (token data elements)
     *
     * @param p1 record number
     * @param p2 SFI encoded as (SFI << 3) | 4
     * @return READ RECORD response bytes + 9000, or 6A83 if record unknown
     */
    private byte[] buildReadRecordResponse(byte p1, byte p2) {
        int recordNum = p1 & 0xFF;
        int sfi       = (p2 & 0xFF) >> 3;

        if (sfi != 1 || recordNum < 1 || recordNum > 2) {
            return new byte[]{0x6A, (byte)0x83}; // Record not found
        }

        String dpan   = mPrefs.getString(KEY_GPAY_DPAN, DEFAULT_DPAN);
        String expiry = mPrefs.getString(KEY_GPAY_EXP,  DEFAULT_EXPIRY);
        String svc    = mPrefs.getString(KEY_GPAY_SVC,  DEFAULT_SVC_CODE);

        // Build Track 2: PAN D YYMM SVC F
        String t2str = dpan + "D" + expiry + svc + "F";
        if (t2str.length() % 2 != 0) t2str += "F";
        byte[] t2 = packBcdTrack2(t2str);

        byte[] panBcd  = packBcd(dpan);
        byte[] expDate = NFCLogger.hexToBytes(expiry + "00"); // YYMMDD

        // Record 1: Track 2 Equivalent Data
        if (recordNum == 1) {
            byte innerLen = (byte)(2 + t2.length);
            byte[] rec = new byte[2 + innerLen + 2];
            int off = 0;
            rec[off++] = 0x70;               // Record Template
            rec[off++] = innerLen;
            rec[off++] = 0x57;               // Tag 57: Track 2 Equivalent Data
            rec[off++] = (byte) t2.length;
            System.arraycopy(t2, 0, rec, off, t2.length); off += t2.length;
            rec[off++] = (byte)0x90;
            rec[off]   = 0x00;
            return rec;
        }

        // Record 2: PAN + Expiry + PAN Seq Num
        int innerLen = 2 + panBcd.length + 2 + expDate.length + 3;
        byte[] rec = new byte[2 + innerLen + 2];
        int off = 0;
        rec[off++] = 0x70; rec[off++] = (byte) innerLen;
        rec[off++] = 0x5A; rec[off++] = (byte) panBcd.length;
        System.arraycopy(panBcd, 0, rec, off, panBcd.length); off += panBcd.length;
        rec[off++] = 0x5F; rec[off++] = 0x24; rec[off++] = (byte) expDate.length;
        System.arraycopy(expDate, 0, rec, off, expDate.length); off += expDate.length;
        rec[off++] = 0x5F; rec[off++] = 0x34; rec[off++] = 0x01; // PAN Seq = 01
        rec[off++] = (byte)0x90; rec[off] = 0x00;
        return rec;
    }

    /**
     * GENERATE AC response — Application Request Cryptogram (ARQC).
     *
     * <p>Returns Response Template Format 2 (77) with a dummy 8-byte cryptogram.
     * The Python relay host replaces this with a genuine VTS/MDES token cryptogram
     * when relay mode is active.
     *
     * <p>Spec ref: EMVCo Book 2 § 8.1.2 (GENERATE AC response)
     *             VTS Tokenization Spec § 5 (Cryptogram Computation)
     *
     * @return GENERATE AC response bytes + 9000
     */
    private byte[] buildGenerateAcResponse() {
        int atc = mPrefs.getInt(KEY_ATC, 0);

        return new byte[]{
            // 77 1E — Response Message Template Format 2
            0x77, 0x1E,
              // 9F 27 01 40 — CID: ARQC (0x40)
              (byte)0x9F, 0x27, 0x01, 0x40,
              // 9F 26 08 — Application Cryptogram (placeholder)
              (byte)0x9F, 0x26, 0x08,
                0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF, 0x00, 0x11, 0x22, 0x33,
              // 9F 36 02 — ATC
              (byte)0x9F, 0x36, 0x02,
                (byte)((atc >> 8) & 0xFF), (byte)(atc & 0xFF),
              // 9F 10 12 — Issuer Application Data (VTS custom IAD)
              (byte)0x9F, 0x10, 0x12,
                0x0F, 0x01, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // SW: 90 00
            (byte)0x90, 0x00
        };
    }

    // ── ATC ───────────────────────────────────────────────────────────────

    /**
     * Increment and persist the Application Transaction Counter.
     * Spec ref: EMVCo Book 2 § 8.1 (ATC management)
     */
    private void incrementAtc() {
        int atc = (mPrefs.getInt(KEY_ATC, 0) + 1) & 0xFFFF;
        mPrefs.edit().putInt(KEY_ATC, atc).apply();
    }

    // ── BCD packing ───────────────────────────────────────────────────────

    /** Pack decimal-digit string into packed BCD bytes. */
    private static byte[] packBcd(String digits) {
        if (digits == null) digits = "";
        if (digits.length() % 2 != 0) digits += "0";
        byte[] out = new byte[digits.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(digits.charAt(i * 2),     10);
            int lo = Character.digit(digits.charAt(i * 2 + 1), 10);
            out[i] = (byte)((hi << 4) | (lo & 0xF));
        }
        return out;
    }

    /** Pack Track 2 string (digits + 'D' sep + 'F' pad) into packed BCD. */
    private static byte[] packBcdTrack2(String t) {
        if (t.length() % 2 != 0) t += "F";
        byte[] out = new byte[t.length() / 2];
        for (int i = 0; i < out.length; i++) {
            char c1 = t.charAt(i * 2);
            char c2 = t.charAt(i * 2 + 1);
            int hi = (c1 == 'D') ? 0xD : (c1 == 'F') ? 0xF : Character.digit(c1, 10);
            int lo = (c2 == 'D') ? 0xD : (c2 == 'F') ? 0xF : Character.digit(c2, 10);
            out[i] = (byte)((hi << 4) | (lo & 0xF));
        }
        return out;
    }
}
