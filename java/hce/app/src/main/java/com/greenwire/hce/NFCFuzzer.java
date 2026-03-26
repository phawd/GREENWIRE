package com.greenwire.hce;

import android.nfc.tech.IsoDep;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import java.io.IOException;
import java.util.Random;

/**
 * NFCFuzzer — malformed APDU sequence generator for NFC target testing.
 *
 * <p>The fuzzer operates in two modes:
 * <ol>
 *   <li><b>Outgoing (tag fuzzing)</b>: A connected {@link IsoDep} tag is passed
 *       to {@link #fuzzTag(IsoDep, int)}.  The fuzzer sends progressively
 *       malformed APDU sequences and logs each response.</li>
 *   <li><b>HCE response injection</b>: {@link #generateFuzzResponse(byte[])}
 *       is called from an HCE service.  Returns a deliberately malformed or
 *       unexpected response to confuse reader error-handling paths.</li>
 * </ol>
 *
 * <h3>Fuzzing strategies</h3>
 * <ol>
 *   <li><b>Wrong Lc/Le</b>: Lc claims N bytes but data field is M ≠ N bytes.</li>
 *   <li><b>Unknown CLA/INS</b>: Random class and instruction bytes outside the
 *       ISO 7816-4 / EMVCo reserved ranges.</li>
 *   <li><b>Invalid AID in SELECT</b>: SELECT by DF Name with a malformed or
 *       zero-length AID.</li>
 *   <li><b>Oversized data</b>: Lc=255 with correspondingly large (or short)
 *       data field.</li>
 *   <li><b>Status word confusion</b>: When acting as HCE, respond to
 *       GET PROCESSING OPTIONS with 6A82 (file not found).</li>
 * </ol>
 *
 * <p>All APDU commands sent and responses received are logged via {@link NFCLogger}.
 *
 * <p>Spec ref:
 * <ul>
 *   <li>ISO/IEC 7816-4 § 5 (APDU structure — command and response)</li>
 *   <li>EMVCo Contactless Specifications Book C-2 (EMV transaction flow)</li>
 *   <li>OWASP Mobile Security Testing Guide — NFC fuzzing section</li>
 * </ul>
 */
public class NFCFuzzer {

    private static final String TAG = "GW-Fuzzer";

    // ── Fuzzing strategy constants ────────────────────────────────────────

    /** Strategy index: wrong Lc/Le mismatch. */
    public static final int STRATEGY_WRONG_LC       = 0;
    /** Strategy index: unknown CLA/INS byte combinations. */
    public static final int STRATEGY_UNKNOWN_INS    = 1;
    /** Strategy index: invalid AID in SELECT command. */
    public static final int STRATEGY_INVALID_AID    = 2;
    /** Strategy index: oversized (255-byte) data field. */
    public static final int STRATEGY_OVERSIZED_DATA = 3;
    /** Strategy index: status-word confusion (HCE mode). */
    public static final int STRATEGY_SW_CONFUSION   = 4;
    /** Total number of strategies. */
    public static final int NUM_STRATEGIES           = 5;

    // ── Known valid INS bytes (used to generate "unknown" ones) ──────────
    /** INS bytes used in normal EMV flow — fuzzer avoids these for unknown-INS strategy. */
    private static final byte[] KNOWN_INS = {
        (byte)0xA4, (byte)0xA8, (byte)0xAE, (byte)0xB2, (byte)0xCA,
        (byte)0x2A, (byte)0x84, (byte)0x82, (byte)0x88, (byte)0xB0,
        0x20, 0x24, 0x46, 0x48
    };

    // ── State ─────────────────────────────────────────────────────────────
    private final NFCLogger  mLogger;
    private final Random     mRandom;

    /** Background HandlerThread used for asynchronous tag fuzzing. */
    private HandlerThread mFuzzThread;
    private Handler       mFuzzHandler;

    /** Set to false by {@link #stopFuzz()} to abort a running session. */
    private volatile boolean mFuzzing = false;

    // ── Construction ─────────────────────────────────────────────────────

    /**
     * Create a new NFCFuzzer.
     *
     * @param logger {@link NFCLogger} to which all fuzz APDUs are written
     */
    public NFCFuzzer(NFCLogger logger) {
        mLogger = logger;
        mRandom = new Random();
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Start fuzzing a physical NFC tag.  All strategies are cycled in order;
     * each strategy sends {@code iterationsPerStrategy} APDUs.
     *
     * <p>Runs on a dedicated background thread so the caller is not blocked.
     * Call {@link #stopFuzz()} to abort.
     *
     * @param tag                    connected {@link IsoDep} tag (must already be connected)
     * @param iterationsPerStrategy  number of fuzz iterations per strategy
     */
    public void fuzzTag(final IsoDep tag, final int iterationsPerStrategy) {
        if (mFuzzing) {
            Log.w(TAG, "Fuzzing already in progress");
            return;
        }
        mFuzzing = true;

        mFuzzThread = new HandlerThread("GW-Fuzz");
        mFuzzThread.start();
        mFuzzHandler = new Handler(mFuzzThread.getLooper());

        mFuzzHandler.post(new Runnable() {
            @Override
            public void run() {
                runFuzzSession(tag, iterationsPerStrategy);
            }
        });
    }

    /**
     * Stop a running fuzz session.  The current APDU in-flight will complete
     * before the loop exits.
     */
    public void stopFuzz() {
        mFuzzing = false;
        if (mFuzzThread != null) {
            mFuzzThread.quitSafely();
        }
        Log.i(TAG, "Fuzz session stopped");
    }

    /**
     * Generate a deliberately malformed response APDU for HCE status-word confusion.
     * Called from HCE services when fuzz mode is active.
     *
     * <p>Strategies applied to HCE responses:
     * <ul>
     *   <li>Return 6A82 (file not found) to GET PROCESSING OPTIONS</li>
     *   <li>Return 6985 (conditions not satisfied) to SELECT AID</li>
     *   <li>Return a random 2-byte status word</li>
     *   <li>Return oversized response data</li>
     * </ul>
     *
     * @param commandApdu the incoming APDU command from the reader
     * @return fuzz response bytes (chosen randomly among strategies)
     */
    public byte[] generateFuzzResponse(byte[] commandApdu) {
        if (commandApdu == null || commandApdu.length < 2) {
            return new byte[]{0x6F, 0x00}; // Unknown error
        }

        byte ins = commandApdu[1];
        int strategy = mRandom.nextInt(NUM_STRATEGIES);

        switch (strategy) {
            case STRATEGY_SW_CONFUSION:
                // Strategy 5: return wrong SW for known commands
                if (ins == (byte)0xA8) {
                    // GET PROCESSING OPTIONS → 6A82 (file not found)
                    Log.d(TAG, "HCE fuzz: GPO → 6A82");
                    return new byte[]{0x6A, (byte)0x82};
                }
                if (ins == (byte)0xA4) {
                    // SELECT → 6985 (conditions not satisfied)
                    Log.d(TAG, "HCE fuzz: SELECT → 6985");
                    return new byte[]{0x69, (byte)0x85};
                }
                break;

            case STRATEGY_OVERSIZED_DATA:
                // Strategy 4: return oversized response (255 bytes + 9000)
                byte[] oversized = new byte[257];
                mRandom.nextBytes(oversized);
                oversized[255] = (byte)0x90;
                oversized[256] = 0x00;
                Log.d(TAG, "HCE fuzz: oversized response (255 bytes)");
                return oversized;

            default:
                // Return a random 2-byte status word
                byte sw1 = (byte)(0x60 + mRandom.nextInt(0x10)); // 60..6F
                byte sw2 = (byte) mRandom.nextInt(0x100);
                Log.d(TAG, String.format("HCE fuzz: random SW %02X%02X", sw1 & 0xFF, sw2 & 0xFF));
                return new byte[]{sw1, sw2};
        }

        // Default fallback: 6F 00 (general error)
        return new byte[]{0x6F, 0x00};
    }

    // ── Private — tag fuzz session ────────────────────────────────────────

    /**
     * Core tag fuzzing loop.  Cycles through all five strategies, sending
     * {@code iterations} APDU commands per strategy and logging the responses.
     *
     * @param tag        connected IsoDep tag
     * @param iterations number of iterations per strategy
     */
    private void runFuzzSession(IsoDep tag, int iterations) {
        Log.i(TAG, "Fuzz session started: " + NUM_STRATEGIES + " strategies × " + iterations);
        int total = 0;

        for (int strategy = 0; strategy < NUM_STRATEGIES && mFuzzing; strategy++) {
            Log.d(TAG, "Strategy " + strategy + ": " + strategyName(strategy));

            for (int i = 0; i < iterations && mFuzzing; i++) {
                byte[] fuzzApdu = buildFuzzApdu(strategy, i);
                if (fuzzApdu == null) continue;

                long start = System.currentTimeMillis();
                try {
                    byte[] response = tag.transceive(fuzzApdu);
                    long elapsed = System.currentTimeMillis() - start;
                    mLogger.logResponse(fuzzApdu, response, elapsed);
                    total++;
                    Log.d(TAG, String.format("Fuzz[%d/%d] → %s (%dms)",
                            strategy, i, NFCLogger.bytesToHex(response), elapsed));
                } catch (IOException e) {
                    Log.w(TAG, "Tag error during fuzz iter " + i + ": " + e.getMessage());
                    // Tag may have reset — log and try to continue
                    mLogger.logApdu(fuzzApdu, "C", 0);
                }
            }
        }

        Log.i(TAG, "Fuzz session complete: " + total + " APDU(s) sent");
        mFuzzing = false;
    }

    /**
     * Build a single fuzz APDU for the given strategy and iteration number.
     *
     * @param strategy  strategy index (0–4)
     * @param iteration iteration number within the strategy (used to vary data)
     * @return fuzz APDU bytes, or null if strategy produces no output for this iteration
     */
    private byte[] buildFuzzApdu(int strategy, int iteration) {
        switch (strategy) {

            case STRATEGY_WRONG_LC:
                return buildWrongLcApdu(iteration);

            case STRATEGY_UNKNOWN_INS:
                return buildUnknownInsApdu();

            case STRATEGY_INVALID_AID:
                return buildInvalidAidSelectApdu(iteration);

            case STRATEGY_OVERSIZED_DATA:
                return buildOversizedDataApdu();

            case STRATEGY_SW_CONFUSION:
                // When fuzzing a tag (not HCE), send GPO with wrong data length
                return buildGpoWithWrongData(iteration);

            default:
                return null;
        }
    }

    // ── Strategy builders ─────────────────────────────────────────────────

    /**
     * Strategy 1 — Wrong Lc/Le: SELECT PPSE but with a lying Lc byte.
     *
     * <p>Tests whether the reader/card enforces Lc consistency.
     * ISO 7816-4 § 5.1 requires the card to return 6700 (wrong length) if
     * Lc does not match the actual data field length.
     *
     * @param iter iteration index, used to vary the Lc claim
     * @return malformed APDU: Lc claims (iter+1) bytes but only 1 byte of data present
     */
    private byte[] buildWrongLcApdu(int iter) {
        int claimedLc = (iter % 14) + 1;          // Claim 1–14 bytes
        // CLA=00 INS=A4 P1=04 P2=00 Lc=<claimed> <1 actual byte>
        return new byte[]{
            0x00, (byte)0xA4, 0x04, 0x00,
            (byte) claimedLc,
            (byte) 0xA0                            // Only 1 byte data
        };
    }

    /**
     * Strategy 2 — Unknown CLA/INS: generate random CLA/INS outside known ranges.
     *
     * <p>Spec ref: ISO 7816-4 § 5.4 (class byte), § 6 (instruction byte table)
     *
     * @return APDU with pseudo-random CLA + INS not in {@link #KNOWN_INS}
     */
    private byte[] buildUnknownInsApdu() {
        // CLA: use 0x7x range (reserved, not used by ISO 7816 / EMV)
        byte cla = (byte)(0x70 | mRandom.nextInt(0x10));

        // INS: avoid known instruction bytes
        byte ins;
        do {
            ins = (byte) mRandom.nextInt(0x100);
        } while (isKnownIns(ins));

        // P1, P2: random
        byte p1 = (byte) mRandom.nextInt(0x100);
        byte p2 = (byte) mRandom.nextInt(0x100);

        return new byte[]{ cla, ins, p1, p2 };
    }

    /**
     * Strategy 3 — Invalid AID in SELECT.
     *
     * <p>Tests whether the application/reader handles invalid AID lengths and
     * content gracefully.  Cases covered:
     * <ul>
     *   <li>Zero-length AID (Lc=0)</li>
     *   <li>All-zeros AID of varying lengths</li>
     *   <li>AID with length &gt; 16 (max per ISO 7816-4 § 9.2)</li>
     *   <li>Random byte AID of valid length (5 bytes)</li>
     * </ul>
     *
     * @param iter iteration index controls which sub-case is used
     * @return malformed SELECT APDU
     */
    private byte[] buildInvalidAidSelectApdu(int iter) {
        int subcase = iter % 4;
        switch (subcase) {
            case 0: {
                // Zero-length AID
                return new byte[]{ 0x00, (byte)0xA4, 0x04, 0x00, 0x00 };
            }
            case 1: {
                // AID length 17 (exceeds max of 16 per spec)
                byte[] apdu = new byte[]{ 0x00, (byte)0xA4, 0x04, 0x00, 0x11,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }; // 17 zero bytes
                return apdu;
            }
            case 2: {
                // Valid-length (7) but all-zeros AID
                return new byte[]{ 0x00, (byte)0xA4, 0x04, 0x00, 0x07,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            }
            default: {
                // Random 5-byte AID
                byte[] aid = new byte[5];
                mRandom.nextBytes(aid);
                return new byte[]{ 0x00, (byte)0xA4, 0x04, 0x00, 0x05,
                    aid[0], aid[1], aid[2], aid[3], aid[4] };
            }
        }
    }

    /**
     * Strategy 4 — Oversized data: Lc=255 with 255 random bytes.
     * Tests whether the card rejects overlong data fields.
     *
     * <p>Spec ref: ISO 7816-4 § 5.1.2 (Le/Lc constraints)
     *
     * @return 4 + 1 + 255 = 260 byte APDU with Lc=FF and 255 random bytes
     */
    private byte[] buildOversizedDataApdu() {
        byte[] data = new byte[255];
        mRandom.nextBytes(data);
        byte[] apdu = new byte[5 + 255];
        apdu[0] = 0x00;               // CLA
        apdu[1] = (byte)0xA4;         // INS = SELECT
        apdu[2] = 0x04;               // P1 = select by DF name
        apdu[3] = 0x00;               // P2
        apdu[4] = (byte)0xFF;         // Lc = 255
        System.arraycopy(data, 0, apdu, 5, 255);
        return apdu;
    }

    /**
     * Strategy 5 — GET PROCESSING OPTIONS with wrong/zero data length.
     * Tests whether the card handles a malformed PDOL response.
     *
     * <p>Spec ref: EMVCo Book C-2 § 6.1.1 (PDOL-related data)
     *
     * @param iter iteration index varies the data length
     * @return GPO APDU with malformed data length
     */
    private byte[] buildGpoWithWrongData(int iter) {
        // CLA=80 INS=A8 P1=00 P2=00 Lc=<0 or wrong> data=83 00
        int lc = iter % 3; // 0, 1, or 2 (all wrong for standard PDOL)
        byte[] apdu = new byte[5 + 2];
        apdu[0] = (byte)0x80; apdu[1] = (byte)0xA8; apdu[2] = 0x00; apdu[3] = 0x00;
        apdu[4] = (byte) lc;
        apdu[5] = (byte)0x83; apdu[6] = 0x00; // minimal command template 83 00
        return apdu;
    }

    // ── Utility ───────────────────────────────────────────────────────────

    /** Check whether {@code ins} is in the known valid INS list. */
    private static boolean isKnownIns(byte ins) {
        for (byte k : KNOWN_INS) {
            if (k == ins) return true;
        }
        return false;
    }

    /** Return a human-readable strategy name for logging. */
    private static String strategyName(int strategy) {
        switch (strategy) {
            case STRATEGY_WRONG_LC:       return "Wrong Lc/Le";
            case STRATEGY_UNKNOWN_INS:    return "Unknown CLA/INS";
            case STRATEGY_INVALID_AID:    return "Invalid AID SELECT";
            case STRATEGY_OVERSIZED_DATA: return "Oversized data";
            case STRATEGY_SW_CONFUSION:   return "SW confusion / GPO wrong data";
            default: return "Unknown";
        }
    }
}
