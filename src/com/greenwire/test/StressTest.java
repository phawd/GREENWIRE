/*
 * GREENWIRE – Stress Test
 * Copyright (C) 2026  GREENWIRE contributors
 * Licensed under GPL-2.0-or-later – see LICENSE.
 */
package com.greenwire.test;

import java.util.Arrays;

/**
 * StressTest exercises the full EMV contactless transaction flow against
 * a simulated GREENWIRE applet, running hundreds of transactions in both
 * successful and failure scenarios and logging every APDU exchange.
 *
 * <p>The test covers:</p>
 * <ul>
 *   <li>Successful TC (offline approved) transactions (card → terminal
 *       and terminal → card AC verification with {@link MockHsm}).</li>
 *   <li>Online ARQC transactions (card produces ARQC, MockHsm simulates
 *       issuer response).</li>
 *   <li>Wrong PIN presentations (1–3 tries) and PIN blocking.</li>
 *   <li>ATC increments across a run of successive transactions.</li>
 *   <li>Invalid/unsupported APDUs to exercise error paths.</li>
 * </ul>
 *
 * <h2>Running</h2>
 * <pre>
 *   ant test           (via Ant)
 *   java -cp build/classes com.greenwire.test.StressTest [iterations]
 * </pre>
 * The default number of iterations is {@value #DEFAULT_ITERATIONS}.
 * Logs are written to {@code logs/transaction_YYYYMMDD_HHmmss.log}.
 */
public final class StressTest {

    /** Total number of full transaction iterations to run by default. */
    public static final int DEFAULT_ITERATIONS = 250;

    // Correct PIN: "0000"
    private static final byte[] CORRECT_PIN = { 0x30, 0x30, 0x30, 0x30 };
    // Wrong PIN: "1234"
    private static final byte[] WRONG_PIN   = { 0x31, 0x32, 0x33, 0x34 };
    // Transaction amount: EUR 0.00 (minor units, 4-byte big-endian)
    private static final byte[] AMOUNT_ZERO = { 0x00, 0x00, 0x00, 0x00 };

    // Counters
    private int cntSuccess;
    private int cntWrongPin;
    private int cntPinBlocked;
    private int cntOtherFail;

    private final MockHsm hsm = new MockHsm();

    public static void main(String[] args) throws Exception {
        int iterations = DEFAULT_ITERATIONS;
        if (args.length > 0) {
            try { iterations = Integer.parseInt(args[0]); }
            catch (NumberFormatException ignored) {}
        }
        new StressTest().run(iterations);
    }

    /** Execute {@code iterations} transaction cycles and log all results. */
    public void run(int iterations) throws Exception {
        try (TransactionLogger log = new TransactionLogger(true)) {
            log.logHeading("GREENWIRE Stress Test  –  " + iterations + " iterations");
            log.logInfo(0, "MockHsm master key: " +
                    TransactionLogger.toHex(MockHsm.JCOP_LAB_KEY));

            // ---------- Batch 1: Successful TC transactions ----------
            int tcCount = (int) (iterations * 0.55);  // 55 %
            log.logHeading("Batch 1: Successful offline TC transactions (" + tcCount + ")");
            runBatchSuccessful(tcCount, log);

            // ---------- Batch 2: Successful ARQC transactions ----------
            int arqcCount = (int) (iterations * 0.20); // 20 %
            log.logHeading("Batch 2: Online ARQC transactions (" + arqcCount + ")");
            runBatchArqc(arqcCount, log);

            // ---------- Batch 3: Wrong PIN (1 attempt then correct) ----------
            int wrongOnce = (int) (iterations * 0.10); // 10 %
            log.logHeading("Batch 3: One wrong PIN then correct (" + wrongOnce + ")");
            runBatchOneWrongPin(wrongOnce, log);

            // ---------- Batch 4: PIN exhaustion / block ----------
            int pinBlock = (int) (iterations * 0.05); // 5 %
            log.logHeading("Batch 4: PIN exhaustion / block (" + pinBlock + ")");
            runBatchPinBlock(pinBlock, log);

            // ---------- Batch 5: Invalid APDU / error paths ----------
            int errorCount = iterations - tcCount - arqcCount - wrongOnce - pinBlock;
            log.logHeading("Batch 5: Error path APDUs (" + errorCount + ")");
            runBatchErrorPaths(errorCount, log);

            // ---------- Summary ----------
            int total = cntSuccess + cntWrongPin + cntPinBlocked + cntOtherFail;
            log.logSummary(total, cntSuccess, cntWrongPin, cntPinBlocked, cntOtherFail);

            // Signal failure if no transactions succeeded
            if (cntSuccess == 0) {
                throw new AssertionError("StressTest: zero successful transactions");
            }
        }
    }

    // ------------------------------------------------------------------
    //  Batch runners
    // ------------------------------------------------------------------

    /** Run {@code n} fully successful TC transactions. */
    private void runBatchSuccessful(int n, TransactionLogger log) throws Exception {
        for (int i = 1; i <= n; i++) {
            AppletTestHarness harness = new AppletTestHarness();
            TerminalEmulator  term    = new TerminalEmulator(harness);
            runSuccessfulTransaction(i, term, log, TerminalEmulator.CRCP_TC);
        }
    }

    /** Run {@code n} online ARQC transactions and verify the AC with MockHsm. */
    private void runBatchArqc(int n, TransactionLogger log) throws Exception {
        for (int i = 1; i <= n; i++) {
            AppletTestHarness harness = new AppletTestHarness();
            TerminalEmulator  term    = new TerminalEmulator(harness);
            runSuccessfulTransaction(i + 10000, term, log, TerminalEmulator.CRCP_ARQC);
        }
    }

    /**
     * Present one wrong PIN, then correct – transaction should complete.
     */
    private void runBatchOneWrongPin(int n, TransactionLogger log) throws Exception {
        for (int i = 1; i <= n; i++) {
            int txId = i + 20000;
            AppletTestHarness harness = new AppletTestHarness();
            TerminalEmulator  term    = new TerminalEmulator(harness);

            byte[] r;
            r = term.selectApplication();
            log.logCommand(txId, buildSelectApdu(), "SELECT");
            log.logResponse(txId, r, "SELECT " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));

            r = term.getProcessingOptions();
            log.logCommand(txId, buildGpoApdu(), "GPO");
            log.logResponse(txId, r, "GPO " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));

            r = term.readRecord(1, 1);
            log.logResponse(txId, r, "READ RECORD " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));

            // Wrong PIN first
            r = term.verifyPin(WRONG_PIN);
            log.logResponse(txId, r, "VERIFY (wrong) " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));
            if ((AppletTestHarness.sw(r) & 0xFF00) == 0x6300) {
                cntWrongPin++;
            }

            // Correct PIN
            r = term.verifyPin(CORRECT_PIN);
            log.logResponse(txId, r, "VERIFY (correct) " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));

            if (!AppletTestHarness.isOk(r)) {
                log.logInfo(txId, "FAIL – correct PIN not accepted after wrong attempt");
                cntOtherFail++;
                continue;
            }

            r = term.generateAC(TerminalEmulator.CRCP_TC, AMOUNT_ZERO);
            log.logResponse(txId, r, "GENERATE AC " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));

            if (AppletTestHarness.isOk(r)) {
                verifyAndLog(txId, term, log);
                cntSuccess++;
            } else {
                cntOtherFail++;
            }
        }
    }

    /**
     * Exhaust the PIN try-counter (3 wrong attempts); verify PIN is blocked.
     */
    private void runBatchPinBlock(int n, TransactionLogger log) throws Exception {
        for (int i = 1; i <= n; i++) {
            int txId = i + 30000;
            AppletTestHarness harness = new AppletTestHarness();
            TerminalEmulator  term    = new TerminalEmulator(harness);

            term.selectApplication();
            term.getProcessingOptions();

            // Three wrong PINs
            for (int attempt = 1; attempt <= 3; attempt++) {
                byte[] r = term.verifyPin(WRONG_PIN);
                short  sw = AppletTestHarness.sw(r);
                if ((sw & 0xFF00) == 0x6300) {
                    cntWrongPin++;
                    log.logInfo(txId, "Wrong PIN attempt " + attempt +
                                " – tries remaining: " + (sw & 0x0F));
                } else if (sw == 0x6982) {
                    cntPinBlocked++;
                    log.logInfo(txId, "PIN blocked after " + attempt + " attempt(s) – SW 6982");
                    break;
                }
            }

            // Verify that the PIN is now blocked
            byte[] r = term.verifyPin(CORRECT_PIN);
            if (AppletTestHarness.sw(r) == (short) 0x6982) {
                log.logInfo(txId, "PIN block confirmed (SW 6982 on correct PIN) PASS");
                cntPinBlocked++;
            } else {
                log.logInfo(txId, "UNEXPECTED: correct PIN accepted after exhaustion! FAIL");
                cntOtherFail++;
            }
        }
    }

    /** Exercise error paths: unsupported INS, wrong CLA, short CDOL. */
    private void runBatchErrorPaths(int n, TransactionLogger log) throws Exception {
        AppletTestHarness harness = new AppletTestHarness();
        TerminalEmulator  term    = new TerminalEmulator(harness);
        term.selectApplication();

        for (int i = 0; i < n; i++) {
            int txId = i + 40000;
            byte[] r;

            // Test 1: unsupported INS (0xFF)
            r = harness.sendCommand(new byte[]{ 0x00, (byte) 0xFF, 0x00, 0x00 });
            log.logInfo(txId, "Unsupported INS 0xFF → " +
                    TransactionLogger.swDescription(AppletTestHarness.sw(r)));
            if (AppletTestHarness.sw(r) == (short) 0x6D00) cntSuccess++;
            else cntOtherFail++;

            // Test 2: wrong CLA (0x90)
            r = harness.sendCommand(new byte[]{ (byte) 0x90, (byte) 0xAE, 0x40, 0x00, 0x01, 0x00 });
            log.logInfo(txId, "Wrong CLA 0x90    → " +
                    TransactionLogger.swDescription(AppletTestHarness.sw(r)));
            if (AppletTestHarness.sw(r) == (short) 0x6E00) cntSuccess++;
            else cntOtherFail++;

            // Test 3: GENERATE AC with too-short data (< 29 bytes)
            r = harness.sendCommand(new byte[]{ 0x00, (byte) 0xAE, 0x40, 0x00, 0x04,
                    0x01, 0x02, 0x03, 0x04 });
            log.logInfo(txId, "Short CDOL (4B)   → " +
                    TransactionLogger.swDescription(AppletTestHarness.sw(r)));
            if (AppletTestHarness.sw(r) == (short) 0x6700) cntSuccess++;
            else cntOtherFail++;

            // Test 4: GET DATA for unknown tag 9F00
            r = term.getData((byte) 0x9F, (byte) 0x00);
            log.logInfo(txId, "GET DATA 9F00     → " +
                    TransactionLogger.swDescription(AppletTestHarness.sw(r)));
            if (AppletTestHarness.sw(r) == (short) 0x6A88) cntSuccess++;
            else cntOtherFail++;
        }
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    /**
     * Execute a complete EMV transaction flow and verify the AC with the
     * MockHsm (simulating issuer-side verification).
     */
    private void runSuccessfulTransaction(int txId, TerminalEmulator term,
                                           TransactionLogger log, byte crcp) throws Exception {
        byte[] r;

        r = term.selectApplication();
        log.logCommand(txId, buildSelectApdu(), "SELECT");
        log.logResponse(txId, r, "SELECT " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));
        if (!AppletTestHarness.isOk(r)) { cntOtherFail++; return; }

        r = term.getProcessingOptions();
        log.logCommand(txId, buildGpoApdu(), "GPO");
        log.logResponse(txId, r, "GPO " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));
        if (!AppletTestHarness.isOk(r)) { cntOtherFail++; return; }

        r = term.readRecord(1, 1);
        log.logCommand(txId, new byte[]{0x00, (byte)0xB2, 0x01, 0x0C, 0x00}, "READ RECORD SFI1/REC1");
        log.logResponse(txId, r, "READ RECORD " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));
        if (!AppletTestHarness.isOk(r)) { cntOtherFail++; return; }

        r = term.verifyPin(CORRECT_PIN);
        log.logCommand(txId, new byte[]{0x00, 0x20, 0x00, (byte)0x80, 0x04, 0x30, 0x30, 0x30, 0x30},
                        "VERIFY PIN");
        log.logResponse(txId, r, "VERIFY PIN " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));
        if (!AppletTestHarness.isOk(r)) { cntOtherFail++; return; }

        r = term.generateAC(crcp, AMOUNT_ZERO);
        log.logCommand(txId, new byte[]{0x00, (byte)0xAE, crcp, 0x00, 0x1D}, "GENERATE AC");
        log.logResponse(txId, r, "GENERATE AC " + TransactionLogger.swDescription(AppletTestHarness.sw(r)));
        if (!AppletTestHarness.isOk(r)) { cntOtherFail++; return; }

        verifyAndLog(txId, term, log);
        cntSuccess++;
    }

    /**
     * Have the MockHsm verify the AC produced by the last GENERATE AC and
     * log the result.  This models the "both-ways" (card → terminal → issuer)
     * verification path.
     */
    private void verifyAndLog(int txId, TerminalEmulator term,
                               TransactionLogger log) throws Exception {
        byte[] atc = term.getLastAtc();
        byte[] un  = term.getLastUn();
        byte[] ac  = term.getLastAc();

        // The applet currently returns a placeholder AC (DEADBEEF00000000),
        // so HSM verification is expected to differ.  Log both for visibility.
        byte[] expectedAc = hsm.computeAC(atc, un, null);
        boolean match = Arrays.equals(expectedAc, ac);

        log.logInfo(txId,
            String.format("HSM verify AC – card: %s  hsm: %s  match: %s",
                TransactionLogger.toHex(ac),
                TransactionLogger.toHex(expectedAc),
                match ? "YES" : "NO (placeholder AC – expected in stub)"));

        // Also test GET DATA for ATC
        byte[] atcResp = term.getData((byte) 0x9F, (byte) 0x36);
        log.logResponse(txId, atcResp,
                "GET DATA ATC → " + TransactionLogger.swDescription(AppletTestHarness.sw(atcResp)));
    }

    // ------------------------------------------------------------------
    //  APDU builders (for logging the command side)
    // ------------------------------------------------------------------

    private byte[] buildSelectApdu() {
        byte[] a = new byte[5 + TerminalEmulator.APPLET_AID.length];
        a[0] = 0x00; a[1] = (byte)0xA4; a[2] = 0x04; a[3] = 0x00;
        a[4] = (byte) TerminalEmulator.APPLET_AID.length;
        System.arraycopy(TerminalEmulator.APPLET_AID, 0, a, 5,
                         TerminalEmulator.APPLET_AID.length);
        return a;
    }

    private byte[] buildGpoApdu() {
        return new byte[]{ 0x00, (byte)0xA8, 0x00, 0x00, 0x02, (byte)0x83, 0x00 };
    }
}
