/*
 * GREENWIRE PinLogicApplet
 * ------------------------
 * JavaCard applet for smartcard/EMV/JCOP research and fuzzing.
 * Purpose: Implements PIN logic, APDU handling, and protocol simulation for EMV/ISO 7816/JavaCard.
 * Relative to: GREENWIRE unified smartcard/EMV/JCOP research suite.
 * Protocols: JavaCard (applet/caplet), ISO 7816 (APDU), EMV, GlobalPlatform.
 *
 * This applet is built and deployed using the Gradle script in javacard/applet/build.gradle.
 * See README.md for project and protocol details.
 */
package com.greenwire;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

public class PinLogicApplet extends Applet {

    private static final byte[] HELLO_WORLD = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    private static final byte CLA_GREENWIRE = (byte) 0xB0;
    private static final byte INS_HELLO = (byte) 0x01;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;

    private OwnerPIN pin;
    private byte pinVerificationState;

    private static final byte PIN_STATE_NORMAL = (byte) 0x01;
    private static final byte PIN_STATE_FORCE_DDA = (byte) 0x02;
    private static final byte PIN_STATE_FUZZ = (byte) 0x03;
    private static final byte PIN_STATE_NOT_VERIFIED = (byte) 0x00;


    protected PinLogicApplet(byte[] bArray, short bOffset, byte bLength) {
        // It is good programming practice to allocate memory for sensitive data
        // in the constructor.
        pin = new OwnerPIN((byte) 5, (byte) 4); // 5 tries, 4 digits

        byte[] initialPin = {(byte)'4', (byte)'3', (byte)'2', (byte)'1'};
        pin.update(initialPin, (short) 0, (byte) 4);
        pinVerificationState = PIN_STATE_NOT_VERIFIED;
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new PinLogicApplet(bArray, bOffset, bLength);
    }

    public boolean select() {
        // The applet declines to be selected if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }
        return true;
    }

    public void deselect() {
        // Reset the pin verification state.
        pin.reset();
        pinVerificationState = PIN_STATE_NOT_VERIFIED;
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }

        if (buffer[ISO7816.OFFSET_CLA] == CLA_GREENWIRE) {
            switch (buffer[ISO7816.OFFSET_INS]) {
                case INS_HELLO:
                    apdu.setOutgoing();
                    apdu.setOutgoingLength((short) HELLO_WORLD.length);
                    apdu.sendBytesLong(HELLO_WORLD, (short) 0, (short) HELLO_WORLD.length);
                    break;
                case INS_VERIFY_PIN:
                    verifyPin(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            // Here you would handle standard EMV commands and change behavior based on pinVerificationState
            // For example, in GET PROCESSING OPTIONS or GENERATE AC
            // This is a placeholder for the actual EMV logic
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    private void verifyPin(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // Check for special PINs first
        if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, new byte[]{'0', '0', '0', '0'}, (short)0, (short)4) == 0) {
            pinVerificationState = PIN_STATE_FORCE_DDA;
            pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead); // still check to decrement counter
            return;
        } else if (Util.arrayCompare(buffer, ISO7816.OFFSET_CDATA, new byte[]{'9', '9', '9', '9'}, (short)0, (short)4) == 0) {
            pinVerificationState = PIN_STATE_FUZZ;
            pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead); // still check to decrement counter
            return;
        }

        // Normal PIN check
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        pinVerificationState = PIN_STATE_NORMAL;
    }

    // Dummy methods for transaction processing to illustrate the logic
    private void getProcessingOptions() {
        if (pinVerificationState == PIN_STATE_FORCE_DDA) {
            // Return AFL indicating DDA
        } else {
            // Return normal AFL
        }
    }

    private void generateAC() {
        if (pinVerificationState == PIN_STATE_FUZZ) {
            // Fuzz the cryptogram
        } else {
            // Generate normal cryptogram
        }
    }
}
