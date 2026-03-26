package com.greenwire.hce;

import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * NFCRelaySocket — bidirectional APDU relay between the Android device and the
 * GREENWIRE Python host over TCP.
 *
 * <h3>Connection modes</h3>
 * <ul>
 *   <li><b>USB / ADB forward</b> (default): The GREENWIRE host runs
 *       {@code adb forward tcp:7777 tcp:7777} so that
 *       {@code localhost:7777} on the device reaches the Python process.
 *       Port 7777 is the GREENWIRE relay default.</li>
 *   <li><b>WiFi TCP</b>: Configurable IP address and port.  Useful when
 *       ADB is unavailable or when relaying over a network.</li>
 * </ul>
 *
 * <h3>Protocol</h3>
 * Newline-delimited JSON (JSONL).  Each message is a single JSON object on
 * one line followed by {@code \n}.
 * <pre>
 * Device → Host  (card receives APDU command from reader):
 *   {"dir":"C","apdu":"00A4040007A0000000031010"}
 *
 * Host → Device  (host tells card what to respond):
 *   {"dir":"R","apdu":"6F1A840E325041592E5359532E4444463031A5089000"}
 * </pre>
 *
 * <h3>Threading</h3>
 * {@link #relayApdu(String)} is called from the NFC binder thread inside
 * {@link android.nfc.cardemulation.HostApduService#processCommandApdu}.
 * It writes to the socket and then blocks for up to {@value #APDU_TIMEOUT_MS} ms
 * waiting for the host response.  A separate reconnect loop runs on a
 * {@link HandlerThread}.
 *
 * <p>All socket access (read + write) is guarded by {@code synchronized(mLock)}
 * to prevent interleaving between the relay call and the reconnect logic.
 *
 * <p>Spec ref: GREENWIRE APDU Relay Protocol v1.0 (internal)
 *             RFC 793 (TCP)
 */
public class NFCRelaySocket {

    private static final String TAG = "GW-Relay";

    /** TCP port used when connected via ADB forward (USB mode). */
    public static final int USB_PORT  = 7777;
    /** Default TCP port for WiFi relay mode. */
    public static final int WIFI_PORT = 7778;

    /** Milliseconds to wait for a relay response before returning null. */
    private static final int APDU_TIMEOUT_MS = 500;
    /** Milliseconds between reconnect attempts when the connection is lost. */
    private static final int RECONNECT_DELAY_MS = 2000;
    /** TCP connect timeout in milliseconds. */
    private static final int CONNECT_TIMEOUT_MS = 3000;

    // ── Configuration (mutable via setters before connect()) ─────────────

    private volatile String  mWifiHost  = "192.168.1.100";
    private volatile int     mWifiPort  = WIFI_PORT;
    private volatile boolean mUseWifi   = false;

    // ── State ─────────────────────────────────────────────────────────────

    /** Guards all access to the socket and its streams. */
    private final Object mLock = new Object();

    private volatile boolean mConnected = false;
    private Socket       mSocket;
    private BufferedReader mReader;
    private PrintWriter    mWriter;

    /** Background thread for reconnect loop (does NOT perform I/O during relay). */
    private HandlerThread mReconnectThread;
    private Handler       mReconnectHandler;

    /** Set to false permanently on {@link #shutdown()}. */
    private volatile boolean mRunning = false;

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Start the relay socket and begin the persistent reconnect loop.
     * Safe to call multiple times; subsequent calls are no-ops if already running.
     */
    public void start() {
        if (mRunning) return;
        mRunning = true;
        mReconnectThread = new HandlerThread("GW-Relay-RC");
        mReconnectThread.start();
        mReconnectHandler = new Handler(mReconnectThread.getLooper());
        scheduleConnect(0);
    }

    /**
     * Permanently shut down the relay socket.  Active APDU exchanges will
     * return null.  Call from {@link GreenwireApp#onTerminate()} or
     * {@link LabResetManager#performReset()}.
     */
    public void shutdown() {
        mRunning = false;
        synchronized (mLock) {
            closeSocket();
        }
        if (mReconnectThread != null) {
            mReconnectThread.quitSafely();
        }
        Log.i(TAG, "Relay socket shut down");
    }

    /**
     * Configure WiFi relay parameters.  Must be called before {@link #start()}.
     *
     * @param host target host IP address or hostname
     * @param port TCP port on the host
     */
    public void setWifiConfig(String host, int port) {
        mWifiHost = host;
        mWifiPort = port;
    }

    /**
     * Select USB/ADB mode (default) or WiFi TCP mode.
     *
     * @param useWifi {@code true} to use WiFi TCP, {@code false} for
     *                USB ADB forward on {@code localhost:}{@value #USB_PORT}
     */
    public void setUseWifi(boolean useWifi) {
        mUseWifi = useWifi;
    }

    /**
     * Return {@code true} if the relay socket is currently connected to the
     * GREENWIRE host and ready to exchange APDUs.
     */
    public boolean isConnected() {
        return mConnected;
    }

    /**
     * Send an APDU command hex string to the GREENWIRE Python host and block
     * until the response arrives or the timeout expires.
     *
     * <p>This method is designed to be called directly from
     * {@link android.nfc.cardemulation.HostApduService#processCommandApdu}
     * on the binder thread.
     *
     * @param commandHex uppercase hex APDU command bytes (e.g. {@code "00A4040007A0000000031010"})
     * @return uppercase hex response bytes (e.g. {@code "9000"}), or {@code null} on
     *         timeout / disconnection
     */
    public String relayApdu(String commandHex) {
        synchronized (mLock) {
            if (!mConnected || mWriter == null || mReader == null) {
                return null;
            }
            try {
                // Build and send JSON command line: {"dir":"C","apdu":"HEXHEX"}
                JSONObject cmd = new JSONObject();
                cmd.put("dir",  "C");
                cmd.put("apdu", commandHex.toUpperCase(Locale.US));
                mWriter.println(cmd.toString());
                if (mWriter.checkError()) {
                    handleDisconnect("write error");
                    return null;
                }

                // Read response line within the per-APDU timeout
                // setSoTimeout applies to the next blocking read on this socket
                mSocket.setSoTimeout(APDU_TIMEOUT_MS);
                String line = mReader.readLine();
                mSocket.setSoTimeout(0);

                if (line == null) {
                    handleDisconnect("stream closed by host");
                    return null;
                }

                // Parse: {"dir":"R","apdu":"..."}
                JSONObject resp = new JSONObject(line);
                return resp.optString("apdu", "6985").toUpperCase(Locale.US);

            } catch (SocketTimeoutException e) {
                // Host did not respond within timeout — caller uses fallback
                Log.w(TAG, "relayApdu: timeout after " + APDU_TIMEOUT_MS + "ms");
                return null;
            } catch (IOException | JSONException e) {
                handleDisconnect(e.getMessage());
                return null;
            }
        }
    }

    /**
     * Send a raw string line to the host without waiting for a response.
     * Used by {@link NFCLogger#exportToHost(NFCRelaySocket)}.
     *
     * @param line text to send (a trailing newline will be appended)
     */
    public void sendRaw(String line) {
        synchronized (mLock) {
            if (mConnected && mWriter != null) {
                mWriter.println(line);
            }
        }
    }

    // ── Reconnect loop (runs on mReconnectThread) ─────────────────────────

    /**
     * Schedule a connection attempt after {@code delayMs} milliseconds.
     *
     * @param delayMs delay before attempting, 0 for immediate
     */
    private void scheduleConnect(long delayMs) {
        if (!mRunning) return;
        mReconnectHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (!mRunning) return;
                attemptConnect();
            }
        }, delayMs);
    }

    /**
     * Attempt a single TCP connection to the GREENWIRE host.
     * On success, sets {@link #mConnected} to {@code true}.
     * On failure, schedules a retry after {@value #RECONNECT_DELAY_MS} ms.
     */
    private void attemptConnect() {
        String host = mUseWifi ? mWifiHost : "127.0.0.1";
        int    port = mUseWifi ? mWifiPort : USB_PORT;
        Log.d(TAG, "Connecting to " + host + ":" + port);

        Socket s = null;
        try {
            s = new Socket();
            s.connect(
                    new java.net.InetSocketAddress(host, port),
                    CONNECT_TIMEOUT_MS);
            s.setTcpNoDelay(true);
            s.setSoTimeout(0);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            PrintWriter writer = new PrintWriter(
                    new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8),
                    true /* autoFlush */);

            synchronized (mLock) {
                closeSocket(); // close any previous socket
                mSocket  = s;
                mReader  = reader;
                mWriter  = writer;
                mConnected = true;
            }
            Log.i(TAG, "Relay connected to " + host + ":" + port);

        } catch (IOException e) {
            Log.d(TAG, "Connect failed: " + e.getMessage() + " — retrying in " + RECONNECT_DELAY_MS + "ms");
            if (s != null) try { s.close(); } catch (IOException ignored) {}
            scheduleConnect(RECONNECT_DELAY_MS);
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /**
     * Called when the connection is lost during an active APDU exchange.
     * Closes the socket and schedules a reconnect.
     *
     * @param reason human-readable disconnect reason for the log
     */
    private void handleDisconnect(String reason) {
        Log.w(TAG, "Relay disconnected: " + reason);
        closeSocket();
        scheduleConnect(RECONNECT_DELAY_MS);
    }

    /**
     * Close the current socket and its streams, reset connection state.
     * Must be called while holding {@link #mLock}.
     */
    private void closeSocket() {
        mConnected = false;
        try { if (mWriter != null) mWriter.close(); } catch (Exception ignored) {}
        try { if (mReader != null) mReader.close(); } catch (Exception ignored) {}
        try { if (mSocket != null) mSocket.close(); } catch (Exception ignored) {}
        mWriter = null;
        mReader = null;
        mSocket = null;
    }
}
