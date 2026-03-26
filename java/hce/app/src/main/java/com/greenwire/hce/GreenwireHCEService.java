package com.greenwire.hce;

import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.util.Arrays;
import java.util.Locale;

/**
 * GreenwireHCEService — Payment card emulation via APDU relay.
 *
 * <p>This service handles the complete EMV contactless payment transaction
 * on behalf of any configured payment scheme.  It:
 * <ol>
 *   <li>Registers all major payment AIDs (Visa, Mastercard, Amex, Discover,
 *       JCB, UnionPay) plus the PPSE discovery AID.</li>
 *   <li>On each APDU command: logs it, attempts to relay it to the
 *       GREENWIRE Python host, and returns the host's response.  If the
 *       relay is not connected it falls back to locally-stored token data.</li>
 *   <li>Tracks the Application Transaction Counter (ATC) and increments it
 *       on each GENERATE AC command (INS=AE, ISO 7816-4 § 7.3.3).</li>
 *   <li>Supports configurable status-word injection for testing reader
 *       error-handling paths (6985 conditions not satisfied, 6A82 file not found).</li>
 * </ol>
 *
 * <p>AIDs registered (see {@code res/xml/apduservice_payment.xml}):
 * <ul>
 *   <li>{@code 325041592E5359532E4444463031} — PPSE "2PAY.SYS.DDF01"</li>
 *   <li>{@code A0000000031010} — Visa Credit/Debit</li>
 *   <li>{@code A0000000032010} — Visa Electron</li>
 *   <li>{@code A0000000041010} — Mastercard Credit/Debit</li>
 *   <li>{@code A0000000043060} — Mastercard Maestro</li>
 *   <li>{@code A00000002501}   — American Express</li>
 *   <li>{@code A0000001523010} — Discover / Diners Club</li>
 *   <li>{@code A0000000651010} — JCB</li>
 *   <li>{@code A000000333010101} — UnionPay</li>
 * </ul>
 *
 * <p>Spec ref:
 * <ul>
 *   <li>EMVCo Contactless Specifications for Payment Systems Book C-2 v2.10</li>
 *   <li>ISO/IEC 14443 Parts 1–4 (contactless proximity cards)</li>
 *   <li>ISO/IEC 7816-4 (APDU command/response structure)</li>
 * </ul>
 */
public class GreenwireHCEService extends HostApduService {

    private static final String TAG = "GW-HCE-Pay";

    // ── SharedPreferences keys ────────────────────────────────────────────
    private static final String PREFS_NAME   = "gw_prefs";
    private static final String KEY_DPAN     = "dpan";
    private static final String KEY_EXPIRY   = "expiry";   // YYMM
    private static final String KEY_SVC_CODE = "svc_code";
    private static final String KEY_ATC      = "atc";

    // ── Default test token (configurable via Settings) ────────────────────
    /** Default test DPAN — Visa test PAN (16 digits, passes Luhn). */
    private static final String DEFAULT_DPAN     = "4111111111111111";
    private static final String DEFAULT_EXPIRY   = "2612"; // YYMM = Dec 2026
    private static final String DEFAULT_SVC_CODE = "101";

    // ── Fallback status words ─────────────────────────────────────────────
    /** SW 9000 — Normal completion (ISO 7816-4 § 5.1.3). */
    private static final byte[] SW_9000   = { (byte)0x90, 0x00 };
    /** SW 6985 — Command not allowed: conditions of use not satisfied. */
    private static final byte[] SW_6985   = { 0x69, (byte)0x85 };
    /** SW 6A82 — Wrong parameters: file / application not found. */
    private static final byte[] SW_6A82   = { 0x6A, (byte)0x82 };
    /** SW 6D00 — Instruction code not supported. */
    private static final byte[] SW_6D00   = { 0x6D, 0x00 };

    // ── PPSE static fallback response ─────────────────────────────────────
    /**
     * Minimal PPSE FCI response listing Visa and Mastercard AIDs.
     *
     * <p>Structure (TLV, BER-encoded per ISO 7816-4 / EMVCo Book B):
     * <pre>
     * 6F xx   — FCI Template
     *   84 0E  — DF Name = 2PAY.SYS.DDF01
     *     32 50 41 59 2E 53 59 53 2E 44 44 46 30 31
     *   A5 xx  — FCI Proprietary Template
     *     BF 0C xx — FCI Issuer Discretionary Data
     *       61 xx  — Application Template (Visa)
     *         4F 07 A0 00 00 00 03 10 10  — AID
     *         50 04 56 69 73 61           — Label "Visa"
     *         87 01 01                    — Priority 1
     *       61 xx  — Application Template (Mastercard)
     *         4F 07 A0 00 00 00 04 10 10
     *         50 0A ...                   — Label "Mastercard"
     *         87 01 02                    — Priority 2
     * 90 00
     * </pre>
     */
    private static final byte[] PPSE_RESPONSE = {
        // 6F 39 — FCI Template (57 bytes total payload)
        0x6F, 0x39,
          // 84 0E — DF Name: "2PAY.SYS.DDF01"
          (byte)0x84, 0x0E,
            0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31,
          // A5 27 — FCI Proprietary Template
          (byte)0xA5, 0x27,
            // BF 0C 24 — FCI Issuer Discretionary Data
            (byte)0xBF, 0x0C, 0x24,
              // 61 12 — Application Template #1 (Visa)
              0x61, 0x12,
                // 4F 07 — AID: A0000000031010 (Visa Credit/Debit)
                0x4F, 0x07, (byte)0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
                // 50 04 — Label: "Visa"
                0x50, 0x04, 0x56, 0x69, 0x73, 0x61,
                // 87 01 01 — Priority indicator 1
                (byte)0x87, 0x01, 0x01,
              // 61 12 — Application Template #2 (Mastercard)
              0x61, 0x12,
                // 4F 07 — AID: A0000000041010 (Mastercard Credit/Debit)
                0x4F, 0x07, (byte)0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10,
                // 50 04 — Label: "MC  "
                0x50, 0x04, 0x4D, 0x43, 0x20, 0x20,
                // 87 01 02 — Priority indicator 2
                (byte)0x87, 0x01, 0x02,
        // SW: 90 00
        (byte)0x90, 0x00
    };

    // ── Visa Debit FCI fallback response ──────────────────────────────────
    /**
     * Minimal Visa Credit/Debit FCI response to SELECT A0000000031010.
     *
     * <p>Tags:
     * <ul>
     *   <li>84 — DF Name (AID)</li>
     *   <li>A5 — FCI Proprietary Template</li>
     *   <li>50 — Application Label "Visa Debit"</li>
     *   <li>5F 2D — Language Preference "en"</li>
     *   <li>9F 38 — PDOL (list of terminal data elements needed for GPO)</li>
     *   <li>BF 0C — FCI Issuer Discretionary Data</li>
     * </ul>
     *
     * <p>Spec ref: EMVCo Book C-3 § 2.3 (Visa Contactless Payment Specification)
     */
    private static final byte[] VISA_FCI_RESPONSE = {
        // 6F 2B — FCI Template
        0x6F, 0x2B,
          // 84 07 — DF Name: A0000000031010 (Visa Credit/Debit AID)
          (byte)0x84, 0x07, (byte)0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
          // A5 20 — FCI Proprietary Template
          (byte)0xA5, 0x20,
            // 50 0A — Application Label: "Visa Debit"
            0x50, 0x0A, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74,
            // 5F 2D 02 — Language Preference: "en"
            0x5F, 0x2D, 0x02, 0x65, 0x6E,
            // 9F 38 0A — PDOL: request terminal data (amount, currency, date, type, unpredictable)
            (byte)0x9F, 0x38, 0x0A,
              (byte)0x9F, 0x02, 0x06, // 9F02: Amount (6 bytes)
              (byte)0x9F, 0x1A, 0x02, // 9F1A: Terminal Country Code (2 bytes)
              (byte)0x95, 0x05,       // 95:   Terminal Verification Results (5 bytes — no length prefix in PDOL)
        // SW: 90 00
        (byte)0x90, 0x00
    };

    // ── State ─────────────────────────────────────────────────────────────
    private NFCLogger      mLogger;
    private NFCRelaySocket mRelay;
    private SharedPreferences mPrefs;

    // ── HostApduService lifecycle ─────────────────────────────────────────

    @Override
    public void onCreate() {
        super.onCreate();
        mLogger = GreenwireApp.get().getLogger();
        mRelay  = GreenwireApp.get().getRelay();
        mPrefs  = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        Log.i(TAG, "Payment HCE service created");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "Payment HCE service destroyed");
    }

    // ── APDU processing ───────────────────────────────────────────────────

    /**
     * Called by the Android NFC stack on every APDU received from the reader.
     * This method MUST return synchronously; the NFC stack will NAK if it does
     * not receive a response within the field timeout (~1s for ISO 14443-4).
     *
     * <p>Processing order:
     * <ol>
     *   <li>Validate APDU minimum length (4 header bytes)</li>
     *   <li>Log the command via {@link NFCLogger}</li>
     *   <li>If relay is connected, forward to Python host and return response</li>
     *   <li>Otherwise, use local fallback logic</li>
     *   <li>Log the response and return it</li>
     * </ol>
     *
     * @param apdu   raw APDU command bytes from the contactless reader
     * @param extras additional data from the framework (not used)
     * @return       APDU response bytes (data + SW1 SW2)
     */
    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        if (apdu == null || apdu.length < 4) {
            return SW_6985; // Malformed APDU — conditions not satisfied
        }

        long startMs = System.currentTimeMillis();
        String hexIn = NFCLogger.bytesToHex(apdu);
        Log.d(TAG, "APDU ← " + hexIn);

        // Log incoming command
        mLogger.logCommand(apdu);

        // Attempt relay to Python host
        byte[] response = null;
        if (mRelay.isConnected()) {
            String respHex = mRelay.relayApdu(hexIn);
            if (respHex != null && !respHex.isEmpty()) {
                response = NFCLogger.hexToBytes(respHex);
            }
        }

        // Fallback if relay is unavailable or timed out
        if (response == null) {
            response = localFallback(apdu);
        }

        long elapsedMs = System.currentTimeMillis() - startMs;
        Log.d(TAG, "APDU → " + NFCLogger.bytesToHex(response) + " (" + elapsedMs + "ms)");

        // Log command + response pair together
        mLogger.logResponse(apdu, response, elapsedMs);

        // Increment ATC when GENERATE AC is processed (INS = AE, EMVCo Book C-2 § 7.3)
        if (apdu[1] == (byte) 0xAE) {
            incrementAtc();
        }

        return response;
    }

    /**
     * Called by the framework when the NFC field is removed or the terminal
     * deselected the application.
     *
     * @param reason deactivation reason code:
     *               {@link HostApduService#DEACTIVATION_LINK_LOSS} or
     *               {@link HostApduService#DEACTIVATION_DESELECTED}
     */
    @Override
    public void onDeactivated(int reason) {
        Log.i(TAG, "Deactivated reason=" + reason);
    }

    // ── Local fallback (relay not connected) ──────────────────────────────

    /**
     * Provide a locally-computed response when the GREENWIRE relay is not
     * available.  Covers the minimal EMV contactless flow:
     * SELECT PPSE → SELECT AID → GET PROCESSING OPTIONS → GENERATE AC.
     *
     * <p>Spec ref: EMVCo Contactless Specifications Book C-2 § 3 (transaction flow)
     *
     * @param apdu raw APDU command from the reader
     * @return fallback response bytes
     */
    private byte[] localFallback(byte[] apdu) {
        byte cla = apdu[0];
        byte ins = apdu[1];
        byte p1  = apdu[2];
        byte p2  = apdu[3];

        // SELECT (INS = A4)
        // CLA=00 INS=A4 P1=04 P2=00 → SELECT by DF Name (ISO 7816-4 § 11.3.5)
        if (ins == (byte) 0xA4 && p1 == 0x04) {
            return handleSelectFallback(apdu);
        }

        // GET PROCESSING OPTIONS (CLA=80 INS=A8) — EMVCo Book C-2 § 6.1
        if (cla == (byte) 0x80 && ins == (byte) 0xA8) {
            return buildGpoResponse();
        }

        // READ RECORD (INS=B2) — ISO 7816-4 § 7.3.3
        if (ins == (byte) 0xB2) {
            return buildReadRecordResponse(p1, p2);
        }

        // GENERATE AC (CLA=80 INS=AE) — EMVCo Book C-2 § 7.3
        if (cla == (byte) 0x80 && ins == (byte) 0xAE) {
            return buildGenerateAcResponse();
        }

        // COMPUTE CRYPTOGRAPHIC CHECKSUM (CLA=80 INS=2A) — Visa payWave specific
        if (cla == (byte) 0x80 && ins == (byte) 0x2A) {
            return buildGenerateAcResponse(); // same structure
        }

        // Unknown INS — return 6D00 (instruction not supported, ISO 7816-4 § 5.1.4)
        return SW_6D00;
    }

    /**
     * Handle a SELECT by DF Name command.
     *
     * <p>Compares the data field of the SELECT APDU against known AIDs and
     * returns the appropriate FCI response.
     *
     * @param apdu full SELECT APDU bytes
     * @return FCI response or 6A82 (file not found)
     */
    private byte[] handleSelectFallback(byte[] apdu) {
        // Data field starts at byte 5 (after CLA INS P1 P2 Lc)
        if (apdu.length < 5) return SW_6A82;
        int lc      = apdu[4] & 0xFF;
        int dataEnd = 5 + lc;
        if (apdu.length < dataEnd) return SW_6A82;

        byte[] aid = Arrays.copyOfRange(apdu, 5, dataEnd);
        String aidHex = NFCLogger.bytesToHex(aid).toUpperCase(Locale.US);
        Log.d(TAG, "SELECT AID: " + aidHex);

        // PPSE: 2PAY.SYS.DDF01 = 325041592E5359532E4444463031
        if ("325041592E5359532E4444463031".equals(aidHex)) {
            return PPSE_RESPONSE;
        }

        // Visa Credit/Debit (A0000000031010) and Electron (A0000000032010)
        if (aidHex.startsWith("A000000003")) {
            return VISA_FCI_RESPONSE;
        }

        // Mastercard / Maestro / Google Pay (A0000000041010, A0000000043060, A000000004)
        if (aidHex.startsWith("A000000004")) {
            return buildMastercardFciResponse();
        }

        // All other AIDs — file not found
        return SW_6A82;
    }

    /**
     * Build a minimal Mastercard Credit/Debit FCI response.
     *
     * <p>Spec ref: M/Chip Contactless Specifications for Payment Systems § 3
     *
     * @return FCI template bytes + 9000
     */
    private byte[] buildMastercardFciResponse() {
        // Label: "Mastercard" = 4D617374657263617264 (10 bytes)
        return new byte[]{
            // 6F 24 — FCI Template
            0x6F, 0x24,
              // 84 07 — DF Name: A0000000041010 (Mastercard)
              (byte)0x84, 0x07, (byte)0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10,
              // A5 19 — FCI Proprietary Template
              (byte)0xA5, 0x19,
                // 50 0A — Application Label: "Mastercard"
                0x50, 0x0A, 0x4D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x63, 0x61, 0x72, 0x64,
                // 5F 2D 02 — Language Preference: "en"
                0x5F, 0x2D, 0x02, 0x65, 0x6E,
                // 9F 38 03 — PDOL: amount (6 bytes)
                (byte)0x9F, 0x38, 0x06,
                  (byte)0x9F, 0x02, 0x06, // amount authorised
                  (byte)0x9F, 0x1A, 0x02, // terminal country code
            // SW: 90 00
            (byte)0x90, 0x00
        };
    }

    /**
     * Build a GET PROCESSING OPTIONS (GPO) response.
     *
     * <p>Returns Response Template Format 1 (tag 80) containing:
     * <ul>
     *   <li>AIP (Application Interchange Profile, 82): CDA+DDA+SDA, offline capable</li>
     *   <li>AFL (Application File Locator, 94): read SFI=1 records 1–2</li>
     * </ul>
     *
     * <p>Spec ref: EMVCo Book C-2 § 6.1.2 (GET PROCESSING OPTIONS)
     *
     * @return GPO response bytes + 9000
     */
    private byte[] buildGpoResponse() {
        return new byte[]{
            // 80 0E — Response Template Format 1
            (byte)0x80, 0x0E,
              // 82 02 — AIP: 5C 00 = SDA+DDA+CDA capable, offline PIN supported
              (byte)0x82, 0x02, 0x5C, 0x00,
              // 94 08 — AFL: SFI 1 records 1–2 (for READ RECORD), SFI 2 records 1–1
              (byte)0x94, 0x08,
                0x08, 0x01, 0x02, 0x00, // SFI=1, first rec=1, last rec=2, offline=0
                0x10, 0x01, 0x01, 0x01, // SFI=2, first rec=1, last rec=1, offline=1
            // SW: 90 00
            (byte)0x90, 0x00
        };
    }

    /**
     * Build a READ RECORD response for the AFL records.
     *
     * <p>Returns a minimal EMV record template (70) with the Track 2 equivalent
     * data constructed from the stored DPAN and expiry.
     *
     * <p>Track 2 Equivalent Data structure (tag 57):
     * <pre>
     * PAN  D  YYMM  SS  S  FF...
     * where D = separator, YYMM = expiry, SS = service code, FF = padding
     * </pre>
     *
     * <p>Spec ref: EMVCo Book 3 § 10.3 (Track 2 Equivalent Data)
     *
     * @param p1 record number (1 = main record with Track 2, 2 = app record)
     * @param p2 SFI (encoded as (SFI << 3) | 4)
     * @return record bytes + 9000, or 6A83 (record not found) for unknown records
     */
    private byte[] buildReadRecordResponse(byte p1, byte p2) {
        int recordNum = p1 & 0xFF;
        int sfi       = (p2 & 0xFF) >> 3;

        if (sfi == 1 && recordNum == 1) {
            // SFI 1, Record 1: main EMV record with Track 2 Equivalent Data
            return buildTrack2Record();
        }
        if (sfi == 1 && recordNum == 2) {
            // SFI 1, Record 2: Application Expiry Date + PAN
            return buildPanRecord();
        }
        if (sfi == 2 && recordNum == 1) {
            // SFI 2, Record 1: CDOL1 / CDOL2 (Card Risk Management Data)
            return buildCdolRecord();
        }
        // Record not found (ISO 7816-4 § 7.3.3)
        return new byte[]{0x6A, (byte)0x83};
    }

    /**
     * Build the Track 2 Equivalent Data EMV record (SFI 1, Record 1).
     * The DPAN and expiry come from SharedPreferences (or defaults).
     *
     * @return record template 70 containing tag 57 (Track 2 Equiv.) + 9000
     */
    private byte[] buildTrack2Record() {
        String dpan    = mPrefs.getString(KEY_DPAN,     DEFAULT_DPAN);
        String expiry  = mPrefs.getString(KEY_EXPIRY,   DEFAULT_EXPIRY);  // YYMM
        String svcCode = mPrefs.getString(KEY_SVC_CODE, DEFAULT_SVC_CODE);

        // Track 2 Equivalent Data: PAN D YYMM SvcCode Discretionary
        // Stored as packed BCD: each digit = 4 bits, nibble D = separator (0D)
        // Layout: 16-digit PAN (8 bytes) + D (sep) + YYMM (2 bytes) + SC (1.5 bytes) + pad F
        // Packed: PPPPPPPPPPPPPPPP D YYMM SSS F (total max 19 bytes for 16-digit PAN)
        String raw = dpan + "D" + expiry + svcCode + "F";
        // Ensure even number of hex digits (pad right with F if odd length)
        if (raw.length() % 2 != 0) raw += "F";
        byte[] track2 = packBcdWithSeparator(raw);

        // Build TLV: 70 (xx) 57 (yy) <track2>
        byte[] record = new byte[2 + 2 + track2.length];
        record[0] = 0x70;               // EMV Record Template
        record[1] = (byte)(2 + track2.length); // length
        record[2] = 0x57;               // Tag: Track 2 Equivalent Data (EMVCo Book 3 Annex A)
        record[3] = (byte) track2.length;
        System.arraycopy(track2, 0, record, 4, track2.length);

        // Append SW 9000
        byte[] resp = new byte[record.length + 2];
        System.arraycopy(record, 0, resp, 0, record.length);
        resp[record.length]     = (byte)0x90;
        resp[record.length + 1] = 0x00;
        return resp;
    }

    /**
     * Build a simplified application record containing PAN and expiry date.
     *
     * <p>Tags included:
     * <ul>
     *   <li>5A — Application PAN</li>
     *   <li>5F24 — Application Expiry Date (YYMMDD, last day set to 00)</li>
     *   <li>5F34 — PAN Sequence Number (01)</li>
     * </ul>
     *
     * @return EMV record template (70) bytes + 9000
     */
    private byte[] buildPanRecord() {
        String dpan   = mPrefs.getString(KEY_DPAN,   DEFAULT_DPAN);
        String expiry = mPrefs.getString(KEY_EXPIRY, DEFAULT_EXPIRY); // YYMM

        byte[] panBcd  = packBcd(dpan);
        // Expiry as YYMMDD (EMVCo Book 3 Annex A tag 5F24)
        byte[] expDate = NFCLogger.hexToBytes(expiry + "00"); // YYMMDD, day=00

        int totalLen = 2 + panBcd.length + 2 + expDate.length + 2 + 1;
        byte[] record = new byte[2 + totalLen];
        int off = 0;
        record[off++] = 0x70;              // Record Template
        record[off++] = (byte) totalLen;
        record[off++] = 0x5A;              // Tag: Application PAN
        record[off++] = (byte) panBcd.length;
        System.arraycopy(panBcd, 0, record, off, panBcd.length); off += panBcd.length;
        record[off++] = 0x5F; record[off++] = 0x24;  // Tag: Expiry Date
        record[off++] = (byte) expDate.length;
        System.arraycopy(expDate, 0, record, off, expDate.length); off += expDate.length;
        record[off++] = 0x5F; record[off++] = 0x34;  // Tag: PAN Sequence Number
        record[off++] = 0x01;  // value = 01 (sequence 1)

        byte[] resp = new byte[record.length + 2];
        System.arraycopy(record, 0, resp, 0, record.length);
        resp[record.length]     = (byte)0x90;
        resp[record.length + 1] = 0x00;
        return resp;
    }

    /**
     * Build a Card Risk Management record (SFI 2, Record 1) with CDOL1/CDOL2.
     *
     * <p>CDOL = Card Risk Management Data Object List.  This record tells the
     * terminal which data objects to include in the GENERATE AC command.
     *
     * <p>Spec ref: EMVCo Book 3 § 10.6 (Card Risk Management)
     *
     * @return EMV record template (70) bytes + 9000
     */
    private byte[] buildCdolRecord() {
        return new byte[]{
            // 70 18 — Record Template
            0x70, 0x18,
              // 8C 11 — CDOL1: data objects the terminal must include in GENERATE AC
              (byte)0x8C, 0x11,
                (byte)0x9F, 0x02, 0x06, // Amount Authorised (6)
                (byte)0x9F, 0x03, 0x06, // Amount Other (6)
                (byte)0x9F, 0x1A, 0x02, // Terminal Country Code (2)
                (byte)0x95, 0x05,       // TVR (5) — no length tag in CDOL items
                (byte)0x5F, 0x2A, 0x02, // Transaction Currency Code (2)
              // 8D 03 — CDOL2: data for 2nd GENERATE AC (TC/AAC)
              (byte)0x8D, 0x03,
                (byte)0x9F, 0x02, 0x06,
            // SW: 90 00
            (byte)0x90, 0x00
        };
    }

    /**
     * Build a GENERATE AC (ARQC) response.
     *
     * <p>Returns Response Template Format 2 (tag 77) containing:
     * <ul>
     *   <li>9F27 — Cryptogram Information Data (40 = ARQC)</li>
     *   <li>9F26 — Application Cryptogram (8 bytes, dummy value)</li>
     *   <li>9F36 — Application Transaction Counter (2 bytes)</li>
     *   <li>9F10 — Issuer Application Data (18 bytes, dummy value)</li>
     * </ul>
     *
     * <p>The cryptogram value is NOT cryptographically valid — this is a
     * fallback for lab/testing purposes only.  Real cryptograms require the
     * card's UDK (Unique Derived Key) which lives on the Python host.
     *
     * <p>Spec ref: EMVCo Book 2 § 8.1.2 (GENERATE AC command/response)
     *
     * @return GENERATE AC response bytes + 9000
     */
    private byte[] buildGenerateAcResponse() {
        int atc = mPrefs.getInt(KEY_ATC, 0);

        return new byte[]{
            // 77 1E — Response Template Format 2
            0x77, 0x1E,
              // 9F 27 01 — Cryptogram Information Data: 40 = ARQC (Authorisation Request)
              (byte)0x9F, 0x27, 0x01, 0x40,
              // 9F 26 08 — Application Cryptogram (dummy 8 bytes)
              (byte)0x9F, 0x26, 0x08,
                0x12, 0x34, 0x56, 0x78, (byte)0x9A, (byte)0xBC, (byte)0xDE, (byte)0xF0,
              // 9F 36 02 — ATC (Application Transaction Counter)
              (byte)0x9F, 0x36, 0x02,
                (byte)((atc >> 8) & 0xFF), (byte)(atc & 0xFF),
              // 9F 10 12 — Issuer Application Data (18 bytes — dummy)
              (byte)0x9F, 0x10, 0x12,
                0x06, 0x01, 0x0A, 0x03, (byte)0xA0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // SW: 90 00
            (byte)0x90, 0x00
        };
    }

    // ── ATC management ────────────────────────────────────────────────────

    /**
     * Increment and persist the ATC counter.
     * The ATC is a 16-bit unsigned counter that increments on every GENERATE AC
     * and is included in the ARQC data to prevent replay attacks.
     *
     * <p>Spec ref: EMVCo Book 2 § 8.1 (Application Transaction Counter)
     */
    private void incrementAtc() {
        int atc = mPrefs.getInt(KEY_ATC, 0);
        atc = (atc + 1) & 0xFFFF; // 16-bit unsigned wraparound
        mPrefs.edit().putInt(KEY_ATC, atc).apply();
        Log.d(TAG, "ATC incremented to " + atc);
    }

    // ── BCD packing utilities ─────────────────────────────────────────────

    /**
     * Pack a decimal digit string into packed BCD bytes.
     * Each pair of decimal digits becomes one byte.
     *
     * @param digits decimal digit string (must have even length; pad with '0' if needed)
     * @return packed BCD byte array
     */
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

    /**
     * Pack a Track 2 string (digits + 'D' separator + digits + 'F' padding)
     * into packed BCD.  'D' is encoded as nibble 0xD; 'F' as 0xF.
     *
     * @param track2 track 2 string, e.g. "4111111111111111D2612101F"
     * @return packed BCD bytes
     */
    private static byte[] packBcdWithSeparator(String track2) {
        if (track2.length() % 2 != 0) track2 += "F";
        byte[] out = new byte[track2.length() / 2];
        for (int i = 0; i < out.length; i++) {
            char c1 = track2.charAt(i * 2);
            char c2 = track2.charAt(i * 2 + 1);
            int hi = (c1 == 'D') ? 0xD : (c1 == 'F') ? 0xF : Character.digit(c1, 10);
            int lo = (c2 == 'D') ? 0xD : (c2 == 'F') ? 0xF : Character.digit(c2, 10);
            out[i] = (byte)((hi << 4) | (lo & 0xF));
        }
        return out;
    }
}
