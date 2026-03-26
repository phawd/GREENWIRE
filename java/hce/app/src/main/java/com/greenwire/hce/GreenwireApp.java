package com.greenwire.hce;

import android.app.Application;
import android.content.SharedPreferences;
import android.util.Log;

import java.util.UUID;

/**
 * GreenwireApp — Android Application class for GREENWIRE NFC Lab.
 *
 * <p>Singleton entry point that:
 * <ul>
 *   <li>Creates and owns the {@link NFCLogger} and {@link NFCRelaySocket}
 *       singletons used by all HCE services and activities.</li>
 *   <li>Maintains the current lab {@link LabMode} so every component can
 *       inspect and change the active operating mode.</li>
 *   <li>Generates / persists a random per-installation {@code deviceId} used
 *       to identify this lab node to the Python host.</li>
 * </ul>
 *
 * <p>Accessible from any component via {@link #get()}.
 *
 * <p>All HCE services extend {@link android.nfc.cardemulation.HostApduService}
 * and obtain the logger/relay via this class:
 * <pre>
 *   NFCLogger  logger = GreenwireApp.get().getLogger();
 *   NFCRelaySocket relay = GreenwireApp.get().getRelay();
 * </pre>
 */
public class GreenwireApp extends Application {

    private static final String TAG        = "GW-App";
    private static final String PREFS_NAME = "gw_prefs";
    private static final String KEY_DEVICE_ID = "device_id";

    // ── Lab operating modes ──────────────────────────────────────────────

    /**
     * Represents the currently active lab mode.  Changing the mode
     * determines how incoming NFC tags and APDU commands are handled
     * by {@link NFCDispatchActivity} and the HCE services.
     */
    public enum LabMode {
        /** No active lab mode; HCE services idle with fallback responses. */
        IDLE,
        /**
         * Payment HCE relay — Visa/MC/Amex/Discover APDUs forwarded to host.
         * Handled by {@link GreenwireHCEService}.
         */
        PAYMENT_HCE,
        /**
         * Google Pay token relay — VTS/MDES token playback.
         * Handled by {@link GooglePayRelayService}.
         */
        GOOGLEPAY_HCE,
        /**
         * Transit card emulation (Oyster/Suica/Clipper/ORCA/Opal).
         * Handled by {@link TransitHCEService}.
         */
        TRANSIT_HCE,
        /**
         * Physical access card emulation (HID Prox / ISO 14443).
         * Handled by {@link AccessCardHCEService}.
         */
        ACCESS_HCE,
        /**
         * Raw relay mode — all APDU traffic forwarded without processing.
         * Any active HCE service uses the relay unconditionally.
         */
        RELAY,
        /**
         * NFC scan mode — the foreground {@link NFCDispatchActivity} reads
         * all tag types and logs them via {@link NFCLogger}.
         */
        SCAN,
        /**
         * Fuzz mode — {@link NFCFuzzer} sends malformed APDU sequences to
         * any connected tag.
         */
        FUZZ,
        /**
         * Clone mode — {@link TagCloner} captures NDEF and Mifare tag data.
         */
        CLONE
    }

    // ── Singleton ─────────────────────────────────────────────────────────

    private static GreenwireApp sInstance;

    /**
     * Return the singleton Application instance.
     * Safe to call from any thread after {@link #onCreate()} completes.
     */
    public static GreenwireApp get() {
        return sInstance;
    }

    // ── Members ───────────────────────────────────────────────────────────

    private NFCLogger      mLogger;
    private NFCRelaySocket mRelay;
    private volatile LabMode mMode = LabMode.IDLE;
    private String          mDeviceId;

    // ── Application lifecycle ─────────────────────────────────────────────

    @Override
    public void onCreate() {
        super.onCreate();
        sInstance = this;

        Log.i(TAG, "GREENWIRE NFC Lab starting");

        mDeviceId = loadOrGenerateDeviceId();
        mLogger   = new NFCLogger();
        mRelay    = new NFCRelaySocket();

        // Start the relay reconnect loop.  It connects to localhost:7777 by
        // default (USB ADB forward mode).  WiFi parameters can be changed
        // from MainActivity before the first connection attempt succeeds.
        mRelay.start();

        Log.i(TAG, "Device ID: " + mDeviceId);
    }

    @Override
    public void onTerminate() {
        super.onTerminate();
        if (mRelay  != null) mRelay.shutdown();
        if (mLogger != null) mLogger.shutdown();
    }

    // ── Getters / Setters ─────────────────────────────────────────────────

    /** Return the APDU traffic logger singleton. */
    public NFCLogger getLogger() {
        return mLogger;
    }

    /** Return the TCP relay socket singleton. */
    public NFCRelaySocket getRelay() {
        return mRelay;
    }

    /** Return the currently active lab operating mode. */
    public LabMode getMode() {
        return mMode;
    }

    /**
     * Change the active lab mode.  HCE services and {@link NFCDispatchActivity}
     * read this on every APDU / tag event.
     *
     * @param mode new operating mode
     */
    public void setMode(LabMode mode) {
        Log.i(TAG, "Mode: " + mMode + " → " + mode);
        mMode = mode;
    }

    /**
     * Return the persistent device identifier string.  Regenerated by
     * {@link LabResetManager#performReset()}.
     */
    public String getDeviceId() {
        return mDeviceId;
    }

    /**
     * Regenerate and persist a new random device ID.
     * Called by {@link LabResetManager#performReset()}.
     *
     * @return the new device ID string
     */
    public String regenerateDeviceId() {
        mDeviceId = UUID.randomUUID().toString();
        getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                .edit()
                .putString(KEY_DEVICE_ID, mDeviceId)
                .apply();
        Log.i(TAG, "New device ID: " + mDeviceId);
        return mDeviceId;
    }

    // ── Private helpers ───────────────────────────────────────────────────

    /**
     * Load the device ID from SharedPreferences, or generate and persist a new
     * random UUID if none exists (first run).
     *
     * @return persisted or newly-generated device ID string
     */
    private String loadOrGenerateDeviceId() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String id = prefs.getString(KEY_DEVICE_ID, null);
        if (id == null || id.isEmpty()) {
            id = UUID.randomUUID().toString();
            prefs.edit().putString(KEY_DEVICE_ID, id).apply();
            Log.i(TAG, "Generated new device ID: " + id);
        }
        return id;
    }
}
