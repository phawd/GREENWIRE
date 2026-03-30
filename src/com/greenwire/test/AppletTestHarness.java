/*
 * GREENWIRE – Applet Test Harness
 * Copyright (C) 2026  GREENWIRE contributors
 * Licensed under GPL-2.0-or-later – see LICENSE.
 */
package com.greenwire.test;

import com.greenwire.wallet.GreenWireApplet;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * AppletTestHarness wraps a {@link GreenWireApplet} instance and drives it
 * as if a real Java Card runtime were present.
 *
 * <p>Usage:</p>
 * <pre>
 *   AppletTestHarness h = new AppletTestHarness();
 *   byte[] resp = h.sendCommand(new byte[]{0x00, (byte)0xA8, 0x00, 0x00, 0x02, (byte)0x83, 0x00});
 *   short sw = AppletTestHarness.sw(resp);
 * </pre>
 *
 * <p>The harness catches {@link ISOException} thrown by the applet and appends
 * the SW as the last two bytes of the returned buffer, matching the on-card
 * behaviour seen by a terminal.</p>
 */
public final class AppletTestHarness {

    private final GreenWireApplet applet;

    /** Instruction byte for SELECT */
    private static final byte INS_SELECT = (byte) 0xA4;

    /** Create a harness with a freshly installed applet. */
    public AppletTestHarness() {
        applet = GreenWireApplet.createForTest();
    }

    /**
     * Send a raw APDU command to the applet and return the full response
     * (data bytes followed by 2-byte SW).
     *
     * @param commandApdu raw command bytes
     * @return response data + SW (2 bytes)
     */
    public byte[] sendCommand(byte[] commandApdu) {
        APDU apdu = APDU.createForTest(commandApdu);
        short sw  = ISO7816.SW_NO_ERROR;

        try {
            // SELECT triggers the lifecycle select() before process()
            if (commandApdu.length > 1 && commandApdu[1] == INS_SELECT) {
                applet.select();
            }
            applet.process(apdu);
        } catch (ISOException e) {
            sw = e.getReason();
        } catch (Exception e) {
            sw = ISO7816.SW_UNKNOWN;
        }

        byte[] responseData = apdu.getResponseData();
        byte[] result = new byte[responseData.length + 2];
        System.arraycopy(responseData, 0, result, 0, responseData.length);
        result[result.length - 2] = (byte) ((sw >> 8) & 0xFF);
        result[result.length - 1] = (byte) (sw        & 0xFF);
        return result;
    }

    /**
     * Convenience: re-select the application (simulates card power-up or
     * explicit re-selection).
     */
    public void reselect() {
        applet.deselect();
        applet.select();
    }

    /** Access the underlying applet for state inspection (e.g. ATC). */
    public GreenWireApplet getApplet() {
        return applet;
    }

    // ------------------------------------------------------------------
    //  Static helpers
    // ------------------------------------------------------------------

    /** Extract the status word from the last 2 bytes of a response. */
    public static short sw(byte[] response) {
        if (response == null || response.length < 2) return (short) 0x6F00;
        return (short) (((response[response.length - 2] & 0xFF) << 8) |
                         (response[response.length - 1] & 0xFF));
    }

    /** Return the data portion of a response (everything except the SW). */
    public static byte[] data(byte[] response) {
        if (response == null || response.length <= 2) return new byte[0];
        byte[] data = new byte[response.length - 2];
        System.arraycopy(response, 0, data, 0, data.length);
        return data;
    }

    /** True if the SW indicates a successful completion (9000). */
    public static boolean isOk(byte[] response) {
        return sw(response) == ISO7816.SW_NO_ERROR;
    }

    /** True if the SW is a PIN tries-remaining warning (63Cx). */
    public static boolean isPinWarning(byte[] response) {
        return (sw(response) & 0xFF00) == 0x6300;
    }
}
