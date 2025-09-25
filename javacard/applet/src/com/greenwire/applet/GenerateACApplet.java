package com.greenwire.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util; 

public class GenerateACApplet extends Applet {

    private static final byte INS_GENERATE_AC = (byte) 0xAE;

    /**
     * Constructs a new instance of the GenerateACApplet.
     * Initialize fields and resources required by the applet here.
     */
    private GenerateACApplet() {
        // Applet constructor - initialize fields if needed
    }

    /**
     * Installs the GenerateACApplet and registers it with the JCRE.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new GenerateACApplet().register();
    }

    @Override
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }

        if (buffer[ISO7816.OFFSET_INS] == INS_GENERATE_AC) {
            generateAC(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void generateAC(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Example: Generate a dummy cryptogram
        byte[] cryptogram = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
        Util.arrayCopyNonAtomic(cryptogram, (short) 0, buffer, (short) 0, (short) cryptogram.length);

        apdu.setOutgoingAndSend((short) 0, (short) cryptogram.length);
    }
}

