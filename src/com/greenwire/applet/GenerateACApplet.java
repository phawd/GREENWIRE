package com.greenwire.applet;

import javacard.framework.*;
import cryptography.hazmat.primitives.asymmetric.rsa;

public class GenerateACApplet extends Applet {

    private static final byte INS_GENERATE_AC = (byte) 0xAE;

    private GenerateACApplet() {
        // Applet constructor
    }

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

repositories {
    mavenCentral()
}

dependencies {
    compileOnly files(jcApiJar)
    compileOnly files(jcConverterJar)
}
