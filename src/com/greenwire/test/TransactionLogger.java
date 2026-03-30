/*
 * GREENWIRE – Transaction Logger
 * Copyright (C) 2026  GREENWIRE contributors
 * Licensed under GPL-2.0-or-later – see LICENSE.
 */
package com.greenwire.test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * TransactionLogger writes every APDU exchange to both the console
 * and a timestamped file under {@code logs/}.
 *
 * <p>Each line is prefixed with a wall-clock timestamp and a direction
 * arrow so that the full duplex conversation can be replayed:</p>
 * <pre>
 *   [0001] 14:00:00.123  >>  00 A4 04 00 09 A0000000031049100100
 *   [0001] 14:00:00.124  <<  90 00  (SELECT OK)
 * </pre>
 */
public final class TransactionLogger implements AutoCloseable {

    private static final SimpleDateFormat TS_FMT =
            new SimpleDateFormat("HH:mm:ss.SSS");
    private static final SimpleDateFormat FILE_FMT =
            new SimpleDateFormat("yyyyMMdd_HHmmss");

    private final PrintWriter writer;
    private final boolean echoToConsole;

    /**
     * Open a new log file inside the {@code logs/} directory.
     *
     * @param echoToConsole if {@code true}, every log line is also printed
     *                      to {@code System.out}
     * @throws IOException if the log file cannot be created
     */
    public TransactionLogger(boolean echoToConsole) throws IOException {
        this.echoToConsole = echoToConsole;
        File logDir = new File("logs");
        if (!logDir.exists() && !logDir.mkdirs()) {
            throw new IOException("Cannot create logs/ directory");
        }
        String filename = "logs/transaction_" + FILE_FMT.format(new Date()) + ".log";
        writer = new PrintWriter(new FileWriter(filename, true));
        writeLine("=== GREENWIRE Transaction Log  started " +
                  new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()) + " ===");
    }

    /** Log an outgoing (terminal → card) APDU command. */
    public void logCommand(int txNum, byte[] apdu, String description) {
        String hex = toHex(apdu);
        writeLine(String.format("[%04d] %s  >>  %s  (%s)",
                txNum, TS_FMT.format(new Date()), hex, description));
    }

    /** Log an incoming (card → terminal) APDU response. */
    public void logResponse(int txNum, byte[] response, String description) {
        String hex = toHex(response);
        writeLine(String.format("[%04d] %s  <<  %s  (%s)",
                txNum, TS_FMT.format(new Date()), hex, description));
    }

    /** Log a free-form information message (no direction arrow). */
    public void logInfo(int txNum, String message) {
        writeLine(String.format("[%04d] %s      %s",
                txNum, TS_FMT.format(new Date()), message));
    }

    /** Log a section separator / heading. */
    public void logHeading(String text) {
        String line = "--- " + text + " ---";
        writeLine(line);
    }

    /** Write summary statistics at the end of a stress test. */
    public void logSummary(int total, int success, int wrongPin,
                            int pinBlocked, int otherFail) {
        writeLine("");
        writeLine("=== SUMMARY ===");
        writeLine(String.format("  Total transactions  : %d", total));
        writeLine(String.format("  Successful          : %d", success));
        writeLine(String.format("  Wrong PIN           : %d", wrongPin));
        writeLine(String.format("  PIN blocked         : %d", pinBlocked));
        writeLine(String.format("  Other failures      : %d", otherFail));
        int failures = total - success;
        writeLine(String.format("  Pass rate           : %.1f%%",
                (total > 0 ? 100.0 * success / total : 0.0)));
        writeLine("=== END ===");
    }

    @Override
    public void close() {
        if (writer != null) writer.close();
    }

    // ------------------------------------------------------------------

    private void writeLine(String line) {
        writer.println(line);
        writer.flush();
        if (echoToConsole) {
            System.out.println(line);
        }
    }

    /** Convert a byte array to space-separated uppercase hex. */
    public static String toHex(byte[] data) {
        if (data == null || data.length == 0) return "(empty)";
        StringBuilder sb = new StringBuilder(data.length * 3);
        for (byte b : data) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    /** Extract the two-byte status word from the end of a response. */
    public static short extractSW(byte[] response) {
        if (response == null || response.length < 2) return (short) 0x6F00;
        int hi = response[response.length - 2] & 0xFF;
        int lo = response[response.length - 1] & 0xFF;
        return (short) ((hi << 8) | lo);
    }

    /** Human-readable description of common SW values. */
    public static String swDescription(short sw) {
        switch (sw & 0xFFFF) {
            case 0x9000: return "OK";
            case 0x6982: return "Security status not satisfied (PIN blocked)";
            case 0x6700: return "Wrong length";
            case 0x6D00: return "INS not supported";
            case 0x6E00: return "CLA not supported";
            case 0x6A83: return "Record not found";
            case 0x6A88: return "Referenced data not found";
            default:
                if ((sw & 0xFF00) == 0x63C0) {
                    return "Wrong PIN – " + (sw & 0x0F) + " tries remaining";
                }
                return String.format("SW %04X", sw & 0xFFFF);
        }
    }
}
