package com.greenwire.hce;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import java.io.File;
import java.util.Locale;

/**
 * LabResetManager — "nuclear" reset for GREENWIRE NFC Lab.
 *
 * <p>Performing a full reset erases all lab state from the device:
 * <ol>
 *   <li>Deletes the entire {@code /sdcard/greenwire/} directory tree
 *       (APDU logs, cloned tag files, exported keys).</li>
 *   <li>Clears all GREENWIRE SharedPreferences: stored tokens, DPAN,
 *       expiry, facility code, ATC counter, relay config.</li>
 *   <li>Disconnects the active {@link NFCRelaySocket} and stops the
 *       reconnect loop.</li>
 *   <li>Resets the ATC counter to 0 in SharedPreferences.</li>
 *   <li>Regenerates a fresh random device ID via
 *       {@link GreenwireApp#regenerateDeviceId()}.</li>
 *   <li>Clears the {@link NFCLogger} in-memory ring buffer and starts a
 *       new session log file.</li>
 *   <li>(Rooted only) Sends SIGHUP to the system NFC daemon to force a
 *       clean re-initialisation of the NFC stack.</li>
 *   <li>Broadcasts {@code com.greenwire.RESET_COMPLETE} so that any
 *       bound components (e.g. {@link MainActivity}) can refresh their UI.</li>
 *   <li>Shows a 3-second countdown Toast before wiping, giving the user a
 *       last chance to see the countdown.</li>
 * </ol>
 *
 * <p>Reset is performed asynchronously on a background thread; the countdown
 * Toasts are posted to the main (UI) thread.
 *
 * <p>Usage:
 * <pre>
 *   LabResetManager.getInstance(context).performReset();
 * </pre>
 */
public class LabResetManager {

    private static final String TAG          = "GW-Reset";
    private static final String PREFS_NAME   = "gw_prefs";
    private static final String ACTION_RESET = "com.greenwire.RESET_COMPLETE";

    /** Singleton instance. */
    private static LabResetManager sInstance;

    private final Context mContext;
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

    // ── Singleton ─────────────────────────────────────────────────────────

    /**
     * Return the singleton {@link LabResetManager}.
     *
     * @param context any valid Android context (Application preferred)
     */
    public static synchronized LabResetManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new LabResetManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private LabResetManager(Context ctx) {
        mContext = ctx;
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Initiate a full lab reset with a 3-second countdown Toast.
     *
     * <p>The countdown Toasts are shown immediately on the UI thread; the
     * actual data wipe starts after the 3-second delay to give the user
     * visible confirmation of what is about to happen.
     */
    public void performReset() {
        Log.w(TAG, "performReset() called — starting countdown");

        // 1. Show countdown Toasts on main thread (3 … 2 … 1)
        showCountdownToast(mContext.getString(R.string.reset_toast_3));
        mMainHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                showCountdownToast(mContext.getString(R.string.reset_toast_2));
            }
        }, 1000);
        mMainHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                showCountdownToast(mContext.getString(R.string.reset_toast_1));
            }
        }, 2000);

        // 2. Perform wipe 3 seconds later on a background thread
        mMainHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        executeReset();
                    }
                }, "GW-Reset-Worker").start();
            }
        }, 3000);
    }

    // ── Private reset steps ───────────────────────────────────────────────

    /**
     * Execute all reset steps synchronously on the reset worker thread.
     * Individual step failures are logged but do not abort the sequence.
     */
    private void executeReset() {
        Log.w(TAG, "=== GREENWIRE RESET EXECUTING ===");

        // Step 1: Delete /sdcard/greenwire/ directory tree
        deleteGwDirectory();

        // Step 2: Clear all SharedPreferences
        clearSharedPreferences();

        // Step 3: Disconnect relay socket
        disconnectRelay();

        // Step 4: ATC is already cleared in step 2; log it explicitly
        Log.i(TAG, "ATC counter reset to 0");

        // Step 5: Regenerate device ID
        GreenwireApp.get().regenerateDeviceId();

        // Step 6: Clear NFCLogger ring buffer and start new session file
        clearLogger();

        // Step 7: On rooted devices — signal the NFC daemon
        signalNfcDaemon();

        // Step 8: Restart relay socket with fresh state
        GreenwireApp.get().getRelay().start();

        Log.w(TAG, "=== GREENWIRE RESET COMPLETE ===");

        // Step 9: Broadcast completion event
        mContext.sendBroadcast(new Intent(ACTION_RESET));

        // Step 10: Show success Toast on main thread
        mMainHandler.post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(mContext,
                        mContext.getString(R.string.reset_toast_done),
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    /**
     * Step 1 — Delete the entire {@code /sdcard/greenwire/} directory tree,
     * including all APDU log files, cloned tag JSON files and any exported keys.
     *
     * <p>Requires {@code WRITE_EXTERNAL_STORAGE} permission (or
     * {@code MANAGE_EXTERNAL_STORAGE} on API 30+).
     */
    private void deleteGwDirectory() {
        try {
            File extDir = Environment.getExternalStorageDirectory();
            File gwDir  = new File(extDir, NFCLogger.GW_DIR);
            if (gwDir.exists()) {
                long count = deleteRecursive(gwDir);
                Log.i(TAG, "Deleted " + count + " file(s) from " + gwDir.getAbsolutePath());
            } else {
                Log.d(TAG, "GW directory does not exist — nothing to delete");
            }
        } catch (Exception e) {
            Log.e(TAG, "deleteGwDirectory failed: " + e.getMessage());
        }
    }

    /**
     * Recursively delete all files and subdirectories under {@code f}.
     *
     * @param f file or directory to delete
     * @return number of files deleted
     */
    private long deleteRecursive(File f) {
        long count = 0;
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) {
                for (File child : children) {
                    count += deleteRecursive(child);
                }
            }
        }
        if (f.delete()) {
            count++;
        } else {
            Log.w(TAG, "Could not delete: " + f.getAbsolutePath());
        }
        return count;
    }

    /**
     * Step 2 — Clear all GREENWIRE SharedPreferences:
     * stored DPAN, expiry, facility code, card number, relay IP/port,
     * ATC counter, device ID, and any other persisted state.
     */
    private void clearSharedPreferences() {
        try {
            SharedPreferences.Editor editor =
                    mContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit();
            editor.clear().apply();
            Log.i(TAG, "SharedPreferences cleared");
        } catch (Exception e) {
            Log.e(TAG, "clearSharedPreferences failed: " + e.getMessage());
        }
    }

    /**
     * Step 3 — Disconnect the active relay socket.
     * The relay will be restarted (step 8) once the reset completes.
     */
    private void disconnectRelay() {
        try {
            NFCRelaySocket relay = GreenwireApp.get().getRelay();
            relay.shutdown();
            Log.i(TAG, "Relay socket disconnected");
        } catch (Exception e) {
            Log.e(TAG, "disconnectRelay failed: " + e.getMessage());
        }
    }

    /**
     * Step 6 — Instruct the {@link NFCLogger} to clear its ring buffer and
     * open a fresh log file for the new session.
     */
    private void clearLogger() {
        try {
            NFCLogger logger = GreenwireApp.get().getLogger();
            logger.clearBuffer();
            Log.i(TAG, "Logger ring buffer cleared");
        } catch (Exception e) {
            Log.e(TAG, "clearLogger failed: " + e.getMessage());
        }
    }

    /**
     * Step 7 — On rooted devices, send SIGHUP to the Android NFC daemon
     * ({@code com.android.nfc}) to force it to re-scan for registered HCE
     * services.  This clears any cached routing tables.
     *
     * <p>This step is a no-op on non-rooted devices and the failure is silently
     * ignored.
     *
     * <p>Shell command equivalent:
     * {@code su -c "pkill -HUP com.android.nfc"}
     */
    private void signalNfcDaemon() {
        if (!RootedNFCHelper.isRooted()) {
            Log.d(TAG, "Not rooted — skipping NFC daemon signal");
            return;
        }
        try {
            // pkill -HUP sends SIGHUP to the NFC process, prompting re-init
            Process p = Runtime.getRuntime().exec(
                    new String[]{"su", "-c", "pkill -HUP com.android.nfc"});
            int exit = p.waitFor();
            Log.i(TAG, "NFC daemon signalled (exit=" + exit + ")");
        } catch (Exception e) {
            Log.w(TAG, "signalNfcDaemon failed (non-rooted?): " + e.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Show a Toast on the main thread.
     *
     * @param message text to display
     */
    private void showCountdownToast(final String message) {
        mMainHandler.post(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(mContext, message, Toast.LENGTH_SHORT).show();
            }
        });
    }
}
