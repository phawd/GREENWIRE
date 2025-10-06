package com.greenwire.applet;

/**
 * Imports core Java Card framework classes required for applet development,
 * including APDU handling, utility functions, and exception management.
 */
import javacard.framework.*;
import javacard.security.*;

/**
 * A simple "Hello World" applet for the GREENWIRE project.
 * This applet can be compiled and converted into a .CAP file for deployment on a Java Card.
 */
public class GreenwireApplet extends Applet {

    // Applet's unique AID (Application Identifier)
    // (Using a non-registered RID for private use)
    private static final byte[] APPLET_AID = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x06, (byte) 0x23, // RID
        (byte) 0x01, (byte) 0x47, (byte) 0x52, (byte) 0x4E, (byte) 0x57, (byte) 0x52 // PIX ("GRNWR")
    };

    // Custom instruction codes (INS)
    private static final byte INS_HELLO = (byte) 0x01;
    private static final byte INS_VERIFY = (byte) 0x20;
    private static final byte INS_GET_SECRET = (byte) 0x02;

    // Constants for PIN
    private static final byte PIN_MAX_TRIES = 3;
    private static final byte PIN_MAX_LENGTH = 8;
    private static final byte[] DEFAULT_PIN = {'1', '2', '3', '4'};

    // Response data
    private static final byte[] HELLO_WORLD = {
        'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'G', 'R', 'E', 'E', 'N', 'W', 'I', 'R', 'E'
    };
    private static final byte[] SECRET_DATA = {
        'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 's', 'e', 'c', 'r', 'e', 't', '!'
    };

    // Instance variables
    private OwnerPIN pin;
    /**
     * Indicates if the PIN has been successfully verified in the current session.
     * This flag is reset upon card reset or applet deselection.
     */
    private boolean pinVerified;

    /**
     * Private constructor. Only the JCRE can create instances of this applet.
     */
    private GreenwireApplet() {
        pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);
        pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);
        pinVerified = false;
    }

    /**
     * Installs the applet on the card.
     * @param bArray the array containing installation parameters.
     * @param bOffset the starting offset in bArray.
     * @param bLength the length in bytes of the parameter data in bArray.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new GreenwireApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /**
     * Resets the PIN verified state when the applet is deselected.
     */
    @Override
    public void deselect() {
        pin.reset();
        pinVerified = false;
    }

    /**
     * Processes an incoming APDU command.
     * @param apdu the incoming APDU object.
     * @throws ISOException with a reason code if an error occurs.
     */
    @Override
    public void process(APDU apdu) throws ISOException {
        // Good practice: If the applet is selected, return and wait for the next command.
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        // We only support our custom instruction class
        if (cla != (byte)0x80) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (ins) {
            case INS_HELLO:
                // Send the "Hello World" response
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) HELLO_WORLD.length);
                Util.arrayCopy(HELLO_WORLD, (short) 0, buffer, (short) 0, (short) HELLO_WORLD.length);
                apdu.sendBytes((short) 0, (short) HELLO_WORLD.length);
                break;
            case INS_VERIFY:
                byte[] pinBuffer = apdu.getBuffer();
                short bytesRead = apdu.setIncomingAndReceive();
                if (pin.check(pinBuffer, ISO7816.OFFSET_CDATA, (byte) bytesRead)) {
                    pinVerified = true;
                }
                // The pin.check() method throws an exception on failure,
                // so we don't need an 'else' block.
                break;
            case INS_GET_SECRET:
                if (!pinVerified) {
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                apdu.setOutgoing();
                apdu.setOutgoingLength((short) SECRET_DATA.length);
                Util.arrayCopy(SECRET_DATA, (short) 0, buffer, (short) 0, (short) SECRET_DATA.length);
                apdu.sendBytes((short) 0, (short) SECRET_DATA.length);
                break;
            default:
                // The instruction is not supported
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}