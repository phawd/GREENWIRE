package com.greenwire.emv;

// Stub classes for JavaCard framework when SDK not available
class APDU {
    public byte[] getBuffer() {
        return new byte[256];
    }

    public short setIncomingAndReceive() {
        return 0;
    }

    public void setOutgoing() {
    }

    public void setOutgoingLength(short len) {
    }

    public void sendBytesLong(byte[] data, short offset, short length) {
    }
}

class Applet {
    public void register() {
    }

    public boolean selectingApplet() {
        return false;
    }
}

class ISO7816 {
    public static final short OFFSET_CLA = 0;
    public static final short OFFSET_INS = 1;
    public static final short OFFSET_P1 = 2;
    public static final short OFFSET_P2 = 3;
    public static final short OFFSET_LC = 4;
    public static final short OFFSET_CDATA = 5;
    public static final short SW_INS_NOT_SUPPORTED = (short) 0x6D00;
    public static final short SW_RECORD_NOT_FOUND = (short) 0x6A83;
    public static final short SW_WRONG_DATA = (short) 0x6A80;
}

class ISOException extends Exception {
    public static void throwIt(short sw) {
        throw new RuntimeException("SW: " + Integer.toHexString(sw));
    }
}

class Util {
    public static void arrayCopy(byte[] src, short srcOff, byte[] dest, short destOff, short length) {
        System.arraycopy(src, srcOff, dest, destOff, length);
    }
}

class CryptoException extends Exception {
}

class KeyBuilder {
    public static final short LENGTH_RSA_1024 = 1024;
}

class KeyPair {
    public static final byte ALG_RSA_CRT = 1;

    public KeyPair(byte alg, short len) {
    }

    public void genKeyPair() throws CryptoException {
    }

    public Object getPrivate() {
        return null;
    }
}

class MessageDigest {
    public static final byte ALG_SHA = 1;
    public static final byte ALG_SHA_256 = 2;

    public static MessageDigest getInstance(byte alg, boolean external) throws CryptoException {
        return new MessageDigest();
    }

    public void doFinal(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
    }
}

class RandomData {
    public static final byte ALG_SECURE_RANDOM = 1;

    public static RandomData getInstance(byte alg) throws CryptoException {
        return new RandomData();
    }

    public void generateData(byte[] buffer, short offset, short length) {
        for (short i = 0; i < length; i++) {
            buffer[(short) (offset + i)] = (byte) (Math.random() * 256);
        }
    }
}

class Signature {
    public static final byte ALG_RSA_SHA_PKCS1 = 1;
    public static final byte MODE_SIGN = 1;

    public static Signature getInstance(byte alg, boolean external) throws CryptoException {
        return new Signature();
    }

    public void init(Object key, byte mode) throws CryptoException {
    }

    public void sign(byte[] in, short inOff, short inLen, byte[] out, short outOff) {
    }
}

/**
 * GREENWIRE EMV RFID Logging Applet
 */
public class EMVRFIDLoggingApplet extends Applet {

    private static final byte[] EMV_AID = {
            (byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10
    };

    private static final short MAX_TRANSACTIONS = 50;
    private static final short TRANSACTION_SIZE = 64;
    private byte[] transactionLog;
    private short transactionCount = 0;
    private short nextTransactionIndex = 0;

    private byte emvState = STATE_IDLE;
    private static final byte STATE_IDLE = 0x00;
    private static final byte STATE_SELECTED = 0x01;
    private static final byte STATE_AUTHENTICATED = 0x02;
    private static final byte STATE_TRANSACTION = 0x03;

    private boolean sdaSupported = true;
    private boolean ddaSupported = true;
    private boolean cdaSupported = true;
    private byte lastAuthMethod = 0x00;

    private RandomData random;
    private MessageDigest sha1;
    private MessageDigest sha256;
    private KeyPair keyPair;
    private Signature signer;

    private short atc = 1;

    private static final byte[] PAN = { (byte) 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    private static final byte[] APPLICATION_LABEL = { (byte) 0x56, 0x49, 0x53, 0x41, 0x20, 0x43, 0x4C, 0x41, 0x53, 0x53,
            0x49, 0x43 };
    private static final byte[] TRACK2_DATA = { (byte) 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, (byte) 0xD2,
            0x01, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EMVRFIDLoggingApplet().register();
    }

    public EMVRFIDLoggingApplet() {
        transactionLog = new byte[(short) (MAX_TRANSACTIONS * TRANSACTION_SIZE)];

        try {
            random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

            keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
            keyPair.genKeyPair();
            signer = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            signer.init(keyPair.getPrivate(), Signature.MODE_SIGN);
        } catch (CryptoException e) {
            random = null;
            sha1 = null;
            sha256 = null;
            keyPair = null;
            signer = null;
        }
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            handleSelect(apdu);
            return;
        }

        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];

        logCommand(buf, ISO7816.OFFSET_LC);

        switch (ins) {
            case (byte) 0xA4:
                handleSelect(apdu);
                break;
            case (byte) 0xA8:
                handleGetProcessingOptions(apdu);
                break;
            case (byte) 0xB2:
                handleReadRecord(apdu);
                break;
            case (byte) 0xAE:
                handleGenerateAC(apdu);
                break;
            case (byte) 0xCA:
                handleGetData(apdu);
                break;
            case (byte) 0x88:
                handleInternalAuthenticate(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void handleSelect(APDU apdu) {
        emvState = STATE_SELECTED;

        byte[] fci = new byte[] {
                (byte) 0x6F, (byte) 0x1E, (byte) 0x84, (byte) 0x07,
                (byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
                (byte) 0xA5, (byte) 0x15, (byte) 0x50, (byte) 0x0B,
                0x56, 0x49, 0x53, 0x41, 0x20, 0x43, 0x4C, 0x41, 0x53, 0x53, 0x49, 0x43,
                (byte) 0x87, (byte) 0x01, (byte) 0x01
        };

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) fci.length);
        apdu.sendBytesLong(fci, (short) 0, (short) fci.length);
    }

    private void handleGetProcessingOptions(APDU apdu) {
        emvState = STATE_TRANSACTION;

        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        short pdolOffset = (short) (ISO7816.OFFSET_CDATA + 2);

        byte[] response = new byte[] {
                (byte) 0x80, (byte) 0x0E, (byte) 0x82, (byte) 0x02,
                (byte) 0x3C, 0x00, (byte) 0x94, (byte) 0x08,
                (byte) 0x08, 0x01, 0x01, 0x00,
                (byte) 0x08, 0x02, 0x02, 0x00
        };

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) response.length);
        apdu.sendBytesLong(response, (short) 0, (short) response.length);
    }

    private void handleReadRecord(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte recordNumber = buf[ISO7816.OFFSET_P1];
        byte sfi = (byte) (buf[ISO7816.OFFSET_P2] >> 3);

        byte[] response = null;

        if (sfi == 1) {
            if (recordNumber == 1) {
                response = buildRecord1();
            } else if (recordNumber == 2) {
                response = buildRecord2();
            }
        } else if (sfi == 2) {
            response = getTransactionRecord(recordNumber);
        }

        if (response != null) {
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) response.length);
            apdu.sendBytesLong(response, (short) 0, (short) response.length);
        } else {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }
    }

    private void handleGenerateAC(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        short lc = apdu.setIncomingAndReceive();

        logTransaction(buf, ISO7816.OFFSET_CDATA, lc, p1);

        byte[] cryptogram = generateCryptogram(p1);

        byte[] response = new byte[32];
        response[0] = (byte) 0x80;
        response[1] = (byte) 0x1E;
        response[2] = (byte) 0x9F;
        response[3] = (byte) 0x27;
        response[4] = (byte) 0x80;

        Util.arrayCopy(cryptogram, (short) 0, response, (short) 5, (short) 8);

        response[13] = (byte) 0x9F;
        response[14] = (byte) 0x36;
        response[15] = (byte) 0x02;
        response[16] = (byte) (atc >> 8);
        response[17] = (byte) (atc & 0xFF);

        atc++;

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) response.length);
        apdu.sendBytesLong(response, (short) 0, (short) response.length);
    }

    private void handleGetData(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        byte[] response = null;

        if (p1 == (byte) 0x9F && p2 == (byte) 0x36) {
            response = new byte[] { (byte) 0x9F, 0x36, 0x02, (byte) (atc >> 8), (byte) (atc & 0xFF) };
        }

        if (response != null) {
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) response.length);
            apdu.sendBytesLong(response, (short) 0, (short) response.length);
        } else {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }

    private void handleInternalAuthenticate(APDU apdu) {
        byte[] signature = new byte[128];
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) signature.length);
        apdu.sendBytesLong(signature, (short) 0, (short) signature.length);
    }

    private byte[] buildRecord1() {
        return new byte[64];
    }

    private byte[] buildRecord2() {
        return new byte[64];
    }

    private byte[] getTransactionRecord(byte recordNumber) {
        return new byte[64];
    }

    private byte[] generateCryptogram(byte acType) {
        return new byte[8];
    }

    private void logCommand(byte[] command, short lcOffset) {
        // Stub implementation
    }

    private void logTransaction(byte[] command, short dataOffset, short dataLength, byte acType) {
        // Stub implementation
    }
}