package com.greenwire.hce;

import android.os.Environment;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Deque;
import java.util.Locale;
import java.util.TimeZone;

/**
 * NFCLogger — APDU traffic logger for GREENWIRE NFC Lab.
 *
 * <p>Every APDU command/response pair is serialised as a single JSON line and
 * appended to a session log file on external storage:
 * {@code /sdcard/greenwire/apdu_log_<TIMESTAMP>.jsonl}
 *
 * <p>An in-memory ring buffer (capacity {@value #RING_CAPACITY}) holds the
 * most recent entries so that {@link MainActivity} can show a live tail view
 * without reading from disk.
 *
 * <p>All disk writes happen on a dedicated {@link android.os.HandlerThread}
 * named {@code GW-Logger-IO}; callers on any thread can call {@link #logApdu}
 * without blocking.
 *
 * <p>Log entry format (newline-delimited JSON, JSONL):
 * <pre>
 * {"ts":"2024-01-15T10:23:45.123Z","dir":"C","cla":"00","ins":"A4",
 *  "p1":"04","p2":"00","lc":14,"data":"325041592E5359532E4444463031",
 *  "sw":"","ms":0}
 * {"ts":"2024-01-15T10:23:45.135Z","dir":"R","cla":"","ins":"",
 *  "p1":"","p2":"","lc":0,"data":"6F1A840E325041592E5359532E4444463031A508...",
 *  "sw":"9000","ms":12}
 * </pre>
 *
 * <p>Spec ref: GREENWIRE APDU Relay Protocol v1.0 (internal)
 *             ISO/IEC 7816-4 Section 5 (APDU structure)
 */
public class NFCLogger {

    private static final String TAG = "GW-Logger";

    /** Maximum number of entries kept in the in-memory ring buffer. */
    private static final int RING_CAPACITY = 1000;

    /** Base directory on external storage for all GREENWIRE output files. */
    public static final String GW_DIR = "greenwire";

    /** Subdirectory for APDU log files. */
    private static final String LOG_SUBDIR = "logs";

    // ── State ────────────────────────────────────────────────────────────

    /** Ring buffer protecting the last RING_CAPACITY log entries. */
    private final Deque<String> mRingBuffer = new ArrayDeque<>(RING_CAPACITY);

    /** Background I/O handler — all disk writes serialised through this. */
    private final android.os.HandlerThread mIoThread;
    private final android.os.Handler       mIoHandler;

    /** Current session log file writer; null until first write succeeds. */
    private BufferedWriter mWriter;

    /** Session start timestamp used in the log filename. */
    private final String mSessionTag;

    /** ISO-8601 timestamp formatter, UTC. */
    private final SimpleDateFormat mTsFmt;

    // ── Construction ─────────────────────────────────────────────────────

    /**
     * Creates a new logger and opens the session log file.
     * Must be called from the Application class or a long-lived context.
     */
    public NFCLogger() {
        mTsFmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
        mTsFmt.setTimeZone(TimeZone.getTimeZone("UTC"));

        mSessionTag = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)
                .format(new Date());

        mIoThread = new android.os.HandlerThread("GW-Logger-IO");
        mIoThread.start();
        mIoHandler = new android.os.Handler(mIoThread.getLooper());

        // Open log file asynchronously so onCreate() returns immediately
        mIoHandler.post(new Runnable() {
            @Override
            public void run() {
                openLogFile();
            }
        });
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Log an APDU command received by the HCE service or dispatched to a tag.
     *
     * @param apdu      raw APDU bytes (command without response)
     * @param direction "C" = command (terminal→card), "R" = response (card→terminal)
     * @param elapsedMs round-trip time in milliseconds (0 if not applicable)
     */
    public void logApdu(final byte[] apdu, final String direction, final long elapsedMs) {
        if (apdu == null || apdu.length == 0) return;

        final String entry = buildEntry(apdu, direction, elapsedMs);

        // Add to ring buffer (always synchronous — fast operation)
        synchronized (mRingBuffer) {
            if (mRingBuffer.size() >= RING_CAPACITY) {
                mRingBuffer.pollFirst(); // drop oldest
            }
            mRingBuffer.addLast(entry);
        }

        // Append to disk on I/O thread
        mIoHandler.post(new Runnable() {
            @Override
            public void run() {
                writeLine(entry);
            }
        });
    }

    /**
     * Convenience overload that logs a raw command APDU (direction = "C",
     * elapsed = 0). The response is logged separately with
     * {@link #logResponse(byte[], byte[], long)}.
     *
     * @param commandApdu APDU bytes as received from the NFC reader
     */
    public void logCommand(byte[] commandApdu) {
        logApdu(commandApdu, "C", 0);
    }

    /**
     * Log a command→response pair together, computing the status word from
     * the last two bytes of the response.
     *
     * @param commandApdu  APDU command bytes
     * @param responseApdu full response including trailing SW1 SW2
     * @param elapsedMs    round-trip processing time in milliseconds
     */
    public void logResponse(byte[] commandApdu, byte[] responseApdu, long elapsedMs) {
        // Log command
        logApdu(commandApdu, "C", 0);
        // Log response
        logApdu(responseApdu, "R", elapsedMs);
    }

    /**
     * Return up to {@code maxLines} of the most recent log entries from the
     * ring buffer as a single newline-separated string. Used by the UI tail view.
     *
     * @param maxLines maximum number of entries to return (10 for the log widget)
     * @return newline-delimited JSON entries, oldest first
     */
    public String getRecentEntries(int maxLines) {
        synchronized (mRingBuffer) {
            int skip = Math.max(0, mRingBuffer.size() - maxLines);
            StringBuilder sb = new StringBuilder();
            int idx = 0;
            for (String line : mRingBuffer) {
                if (idx++ < skip) continue;
                sb.append(line).append('\n');
            }
            return sb.toString().trim();
        }
    }

    /**
     * Clear the in-memory ring buffer. Existing disk log is preserved;
     * a new session file will be started on the next log entry.
     *
     * <p>Called by {@link LabResetManager#performReset()}.
     */
    public void clearBuffer() {
        synchronized (mRingBuffer) {
            mRingBuffer.clear();
        }
        mIoHandler.post(new Runnable() {
            @Override
            public void run() {
                closeWriter();
                openLogFile(); // start fresh session file
            }
        });
    }

    /**
     * Write the entire ring buffer contents over the supplied relay socket.
     * Used for exporting logs from the device to the GREENWIRE Python host.
     *
     * @param relay live {@link NFCRelaySocket} to write to (must be connected)
     */
    public void exportToHost(final NFCRelaySocket relay) {
        if (relay == null || !relay.isConnected()) {
            Log.w(TAG, "exportToHost: relay not connected");
            return;
        }
        mIoHandler.post(new Runnable() {
            @Override
            public void run() {
                synchronized (mRingBuffer) {
                    for (String entry : mRingBuffer) {
                        relay.sendRaw(entry);
                    }
                }
                Log.i(TAG, "exportToHost: sent " + mRingBuffer.size() + " entries");
            }
        });
    }

    /**
     * Shut down the logger — flushes pending writes and closes the log file.
     * Must be called from {@link GreenwireApp#onTerminate()}.
     */
    public void shutdown() {
        mIoHandler.post(new Runnable() {
            @Override
            public void run() {
                closeWriter();
            }
        });
        mIoThread.quitSafely();
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /**
     * Construct a JSON log entry for a single APDU direction.
     *
     * <p>Command APDU layout (ISO 7816-4 Section 5.1):
     * <pre>
     * Offset 0: CLA  (class byte)
     * Offset 1: INS  (instruction byte)
     * Offset 2: P1   (parameter 1)
     * Offset 3: P2   (parameter 2)
     * Offset 4: Lc   (number of data bytes, if present — Case 3/4)
     * Offset 5+: data field (Lc bytes)
     * Last:  Le   (expected response length — Case 2/4)
     * </pre>
     *
     * <p>Response APDU layout:
     * <pre>
     * Bytes 0..N-3: response data
     * Byte  N-2:    SW1
     * Byte  N-1:    SW2
     * </pre>
     */
    private String buildEntry(byte[] apdu, String dir, long elapsedMs) {
        String ts       = mTsFmt.format(new Date());
        String hexFull  = bytesToHex(apdu);
        String cla = "", ins = "", p1 = "", p2 = "", data = "", sw = "";
        int lc = 0;

        if ("C".equals(dir) && apdu.length >= 4) {
            // Parse command APDU header
            cla = String.format(Locale.US, "%02X", apdu[0] & 0xFF);
            ins = String.format(Locale.US, "%02X", apdu[1] & 0xFF);
            p1  = String.format(Locale.US, "%02X", apdu[2] & 0xFF);
            p2  = String.format(Locale.US, "%02X", apdu[3] & 0xFF);
            if (apdu.length > 5) {
                lc   = apdu[4] & 0xFF;
                int dataLen = Math.min(lc, apdu.length - 5);
                data = bytesToHex(apdu, 5, dataLen);
            }
        } else if ("R".equals(dir) && apdu.length >= 2) {
            // Parse response APDU: data + SW1SW2
            int dataLen = apdu.length - 2;
            if (dataLen > 0) {
                data = bytesToHex(apdu, 0, dataLen);
            }
            sw = String.format(Locale.US, "%02X%02X",
                    apdu[apdu.length - 2] & 0xFF,
                    apdu[apdu.length - 1] & 0xFF);
        } else {
            // Malformed / minimal APDU — log raw
            data = hexFull;
        }

        // Build JSON manually (no library dependency in this helper class)
        return String.format(Locale.US,
                "{\"ts\":\"%s\",\"dir\":\"%s\",\"cla\":\"%s\",\"ins\":\"%s\"," +
                "\"p1\":\"%s\",\"p2\":\"%s\",\"lc\":%d,\"data\":\"%s\"," +
                "\"sw\":\"%s\",\"ms\":%d}",
                ts, dir, cla, ins, p1, p2, lc, data, sw, elapsedMs);
    }

    /**
     * Open (or create) the session log file in
     * {@code /sdcard/greenwire/logs/apdu_log_<SESSION_TAG>.jsonl}.
     * Must be called on {@link #mIoThread}.
     */
    private void openLogFile() {
        try {
            File extDir = Environment.getExternalStorageDirectory();
            File gwDir  = new File(extDir, GW_DIR + File.separator + LOG_SUBDIR);
            if (!gwDir.exists() && !gwDir.mkdirs()) {
                Log.e(TAG, "Cannot create log directory: " + gwDir.getAbsolutePath());
                return;
            }
            File logFile = new File(gwDir, "apdu_log_" + mSessionTag + ".jsonl");
            mWriter = new BufferedWriter(
                    new OutputStreamWriter(
                            new FileOutputStream(logFile, true), // append
                            StandardCharsets.UTF_8));
            Log.i(TAG, "Log file: " + logFile.getAbsolutePath());
        } catch (IOException e) {
            Log.e(TAG, "openLogFile failed: " + e.getMessage());
        }
    }

    /**
     * Append a single JSON line to the log file.
     * Must be called on {@link #mIoThread}.
     *
     * @param line complete JSON object string (no trailing newline needed)
     */
    private void writeLine(String line) {
        if (mWriter == null) return;
        try {
            mWriter.write(line);
            mWriter.newLine();
            mWriter.flush();
        } catch (IOException e) {
            Log.e(TAG, "writeLine failed: " + e.getMessage());
        }
    }

    /**
     * Flush and close the current log file writer.
     * Must be called on {@link #mIoThread}.
     */
    private void closeWriter() {
        if (mWriter != null) {
            try {
                mWriter.flush();
                mWriter.close();
            } catch (IOException ignored) {}
            mWriter = null;
        }
    }

    // ── Hex utilities ─────────────────────────────────────────────────────

    /** Convert an entire byte array to an uppercase hex string. */
    static String bytesToHex(byte[] b) {
        if (b == null) return "";
        return bytesToHex(b, 0, b.length);
    }

    /** Convert a sub-range of a byte array to an uppercase hex string. */
    static String bytesToHex(byte[] b, int offset, int length) {
        StringBuilder sb = new StringBuilder(length * 2);
        for (int i = offset; i < offset + length && i < b.length; i++) {
            sb.append(String.format(Locale.US, "%02X", b[i] & 0xFF));
        }
        return sb.toString();
    }

    /** Convert an uppercase hex string to a byte array. */
    static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() == 0) return new byte[0];
        String h = hex.replaceAll("\\s", "");
        int len = h.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(h.substring(i, i + 2), 16);
        }
        return out;
    }
}
