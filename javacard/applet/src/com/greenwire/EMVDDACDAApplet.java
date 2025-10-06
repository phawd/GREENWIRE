/*
 * GREENWIRE EMV DDA/CDA Applet
 * -----------------------------
 * JavaCard applet implementing EMV Dynamic Data Authentication (DDA) and
 * Combined Data Authentication (CDA) for NFC contactless transactions.
 *
 * Features:
 * - EMV transaction processing with DDA/CDA support
 * - Transaction logging in EMV Transaction Log format
 * - Test-friendly APDU commands for GREENWIRE testing framework
 * - Persistent storage of transaction data
 *
 * Protocols: EMV, ISO 7816, JavaCard
 * Relative to: GREENWIRE smartcard/EMV research suite
 */
package com.greenwire;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;

public class EMVDDACDAApplet extends Applet {

    // EMV Constants
    private static final byte[] EMV_AID = {(byte)0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10};
    private static final byte[] PPSE_AID = {(byte)0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31};

    // APDU Commands
    private static final byte CLA_EMV = (byte) 0x00;
    private static final byte CLA_GREENWIRE_TEST = (byte) 0xB0;

    private static final byte INS_SELECT = (byte) 0xA4;
    private static final byte INS_GET_PROCESSING_OPTIONS = (byte) 0xA8;
    private static final byte INS_READ_RECORD = (byte) 0xB2;
    private static final byte INS_GENERATE_AC = (byte) 0xAE;
    private static final byte INS_GET_DATA = (byte) 0xCA;

    // GREENWIRE Test Commands
    private static final byte INS_GET_LOG_COUNT = (byte) 0x01;
    private static final byte INS_GET_LOG_ENTRY = (byte) 0x02;
    private static final byte INS_CLEAR_LOGS = (byte) 0x03;
    private static final byte INS_FORCE_DDA = (byte) 0x04;
    private static final byte INS_FORCE_CDA = (byte) 0x05;

    // EMV Data (initialized but not used in simplified implementation)
    private byte[] afl; // Application File Locator
    private byte[] cdol1; // Card Risk Management Data Object List 1
    private byte[] pdol; // Processing Options Data Object List

    // Transaction Log
    private static final short MAX_TRANSACTIONS = (short) 10;
    private static final short LOG_ENTRY_SIZE = (short) 64; // Size per transaction log entry
    private final byte[] transactionLog;
    private short logCount;
    private short currentLogIndex;

    // Crypto
    private final KeyPair keyPair;
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final Signature signature;
    private final RandomData random;

    // PIN
    private final OwnerPIN pin;

    // State
    private boolean useDDA;
    private boolean useCDA;
    private byte[] currentTransactionData;

    protected EMVDDACDAApplet(byte[] bArray, short bOffset, byte bLength) {
        // Initialize PIN
        pin = new OwnerPIN((byte) 3, (byte) 4);
        byte[] defaultPin = {(byte)'1', (byte)'2', (byte)'3', (byte)'4'};
        pin.update(defaultPin, (short) 0, (byte) 4);

        // Initialize transaction log
        transactionLog = new byte[(short)(MAX_TRANSACTIONS * LOG_ENTRY_SIZE)];
        logCount = 0;
        currentLogIndex = 0;

        // Initialize crypto
        keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        signature.init(privateKey, Signature.MODE_SIGN);
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // Initialize EMV data
        initializeEMVData();

        // Default to DDA
        useDDA = true;
        useCDA = false;

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EMVDDACDAApplet(bArray, bOffset, bLength);
    }

    private void initializeEMVData() {
        // AFL: Application File Locator (simplified)
        afl = new byte[] {
            0x08, 0x01, 0x01, 0x00,  // SFI 1, record 1
            0x08, 0x02, 0x01, 0x00   // SFI 1, record 2
        };

        // PDOL: Processing Options Data Object List (simplified)
        pdol = new byte[] {
            (byte)0x9F, 0x66, 0x04   // Terminal Transaction Qualifiers
        };

        // CDOL1: Card Risk Management Data Object List 1 (simplified)
        cdol1 = new byte[] {
            (byte)0x9F, 0x02, 0x06,  // Amount, Authorized
            (byte)0x9F, 0x03, 0x06,  // Amount, Other
            (byte)0x9F, 0x1A, 0x02,  // Terminal Country Code
            (byte)0x95, 0x05,        // Terminal Verification Results
            (byte)0x5F, 0x2A, 0x02,  // Transaction Currency Code
            (byte)0x9A, 0x03,        // Transaction Date
            (byte)0x9C, 0x01,        // Transaction Type
            (byte)0x9F, 0x37, 0x04   // Unpredictable Number
        };
    }

    @Override
    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }

        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        if (cla == CLA_EMV) {
            processEMVCommand(apdu, ins);
        } else if (cla == CLA_GREENWIRE_TEST) {
            processTestCommand(apdu, ins);
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    private void processEMVCommand(APDU apdu, byte ins) {
        switch (ins) {
            case INS_SELECT:
                processSelect(apdu);
                break;
            case INS_GET_PROCESSING_OPTIONS:
                processGetProcessingOptions(apdu);
                break;
            case INS_READ_RECORD:
                processReadRecord(apdu);
                break;
            case INS_GENERATE_AC:
                processGenerateAC(apdu);
                break;
            case INS_GET_DATA:
                processGetData(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void processTestCommand(APDU apdu, byte ins) {
        switch (ins) {
            case INS_GET_LOG_COUNT:
                getLogCount(apdu);
                break;
            case INS_GET_LOG_ENTRY:
                getLogEntry(apdu);
                break;
            case INS_CLEAR_LOGS:
                clearLogs(apdu);
                break;
            case INS_FORCE_DDA:
                forceDDA(apdu);
                break;
            case INS_FORCE_CDA:
                forceCDA(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void processSelect(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte[] aid = new byte[buffer[ISO7816.OFFSET_LC]];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, aid, (short)0, (short)aid.length);

        // Check if it's our AID or PPSE
        if (Util.arrayCompare(aid, (short)0, EMV_AID, (short)0, (short)EMV_AID.length) == 0 ||
            Util.arrayCompare(aid, (short)0, PPSE_AID, (short)0, (short)PPSE_AID.length) == 0) {
            // Return FCI (File Control Information)
            byte[] fci = {
                (byte)0x6F,  // FCI Template
                (byte)0x1A,  // Length
                (byte)0x84,  // DF Name
                (byte)0x07,  // Length
                (byte)0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,  // AID
                (byte)0xA5,  // FCI Proprietary Template
                (byte)0x11,  // Length
                (byte)0x50,  // Application Label
                (byte)0x0B,  // Length
                'G', 'R', 'E', 'E', 'N', 'W', 'I', 'R', 'E', ' ', 'T', 'E', 'S', 'T',
                (byte)0x87,  // Application Priority Indicator
                (byte)0x01,  // Length
                (byte)0x01   // Priority
            };

            apdu.setOutgoing();
            apdu.setOutgoingLength((short)fci.length);
            apdu.sendBytesLong(fci, (short)0, (short)fci.length);
        } else {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    }

    private void processGetProcessingOptions(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);
        byte[] pdolData = new byte[lc];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pdolData, (short)0, lc);

        // Parse PDOL data and build response
        byte[] response = {
            (byte)0x80,  // Response Message Template Format 1
            (byte)0x0E,  // Length
            (byte)0x82,  // Application Interchange Profile
            (byte)0x02,  // Length
            (byte)0x20, 0x00,  // AIP (SDA supported)
            (byte)0x94,  // Application File Locator
            (byte)0x08,  // Length
            0x08, 0x01, 0x01, 0x00,  // AFL
            0x08, 0x02, 0x01, 0x00
        };

        apdu.setOutgoing();
        apdu.setOutgoingLength((short)response.length);
        apdu.sendBytesLong(response, (short)0, (short)response.length);
    }

    private void processReadRecord(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1]; // Record number
        byte p2 = buffer[ISO7816.OFFSET_P2]; // SFI

        // Simplified: return a basic record
        byte[] record = {
            (byte)0x70,  // Record Template
            (byte)0x1E,  // Length
            (byte)0x9F, 0x42, 0x01, 0x01,  // Application Currency Code
            (byte)0x9F, 0x44, 0x01, 0x02,  // Application Currency Exponent
            (byte)0x9F, 0x05, 0x01, 0x01,  // Application Discretionary Data
            (byte)0x5F, 0x24, 0x03, 0x25, 0x12, 0x31,  // Application Expiration Date
            (byte)0x5F, 0x25, 0x03, 0x20, 0x01, 0x01,  // Application Effective Date
            (byte)0x5F, 0x28, 0x02, 0x08, 0x40   // Issuer Country Code
        };

        apdu.setOutgoing();
        apdu.setOutgoingLength((short)record.length);
        apdu.sendBytesLong(record, (short)0, (short)record.length);
    }

    private void processGenerateAC(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1]; // Reference Control Parameter
        short lc = (short)(buffer[ISO7816.OFFSET_LC] & 0xFF);

        // Read CDOL1 data
        byte[] cdol1Data = new byte[lc];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, cdol1Data, (short)0, lc);

        // Store transaction data for logging
        currentTransactionData = new byte[lc];
        Util.arrayCopy(cdol1Data, (short)0, currentTransactionData, (short)0, lc);

        // Generate cryptogram
        byte[] cryptogram = new byte[8];
        random.generateData(cryptogram, (short)0, (short)8);

        // For DDA/CDA, sign the data
        if (useDDA || useCDA) {
            // Create data to sign (simplified: transaction data + cryptogram)
            byte[] dataToSign = new byte[(short)(cdol1Data.length + cryptogram.length)];
            Util.arrayCopy(cdol1Data, (short)0, dataToSign, (short)0, (short)cdol1Data.length);
            Util.arrayCopy(cryptogram, (short)0, dataToSign, (short)cdol1Data.length, (short)cryptogram.length);

            byte[] signedData = new byte[128]; // RSA 1024 signature
            short sigLen = signature.sign(dataToSign, (short)0, (short)dataToSign.length, signedData, (short)0);

            // Build response with signed data
            byte[] response = new byte[(short)(29 + sigLen)]; // Header + data + signature
            short offset = 0;

            // Cryptogram Information Data
            response[offset++] = (byte)0x80; // CID for AAC/TC/ARQC
            response[offset++] = cryptogram[0];

            // Application Transaction Counter
            response[offset++] = (byte)0x9F;
            response[offset++] = 0x36;
            response[offset++] = 0x02;
            response[offset++] = 0x00;
            response[offset++] = 0x01;

            // Application Cryptogram
            response[offset++] = (byte)0x9F;
            response[offset++] = 0x26;
            response[offset++] = 0x08;
            Util.arrayCopy(cryptogram, (short)0, response, offset, (short)8);
            offset += 8;

            // Issuer Application Data (for CDA)
            if (useCDA) {
                response[offset++] = (byte)0x9F;
                response[offset++] = 0x10;
                response[offset++] = (byte)(2 + sigLen);
                response[offset++] = (byte)0x01; // Format
                response[offset++] = (byte)sigLen;
                Util.arrayCopy(signedData, (short)0, response, offset, sigLen);
                offset += sigLen;
            }

            apdu.setOutgoing();
            apdu.setOutgoingLength(offset);
            apdu.sendBytesLong(response, (short)0, offset);

            // Log the transaction
            logTransaction(cdol1Data, cryptogram, signedData);
        } else {
            // Basic response without DDA/CDA
            byte[] response = {
                (byte)0x80, cryptogram[0],  // CID
                (byte)0x9F, 0x36, 0x02, 0x00, 0x01,  // ATC
                (byte)0x9F, 0x26, 0x08,  // Cryptogram
                cryptogram[0], cryptogram[1], cryptogram[2], cryptogram[3],
                cryptogram[4], cryptogram[5], cryptogram[6], cryptogram[7]
            };

            apdu.setOutgoing();
            apdu.setOutgoingLength((short)response.length);
            apdu.sendBytesLong(response, (short)0, (short)response.length);

            // Log the transaction
            logTransaction(cdol1Data, cryptogram, null);
        }
    }

    private void processGetData(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];

        // Simplified: return some basic data
        byte[] data = {(byte)0x9F, 0x36, 0x02, 0x00, 0x01}; // ATC

        apdu.setOutgoing();
        apdu.setOutgoingLength((short)data.length);
        apdu.sendBytesLong(data, (short)0, (short)data.length);
    }

    private void logTransaction(byte[] transactionData, byte[] cryptogram, byte[] signature) {
        if (logCount >= MAX_TRANSACTIONS) {
            // Overwrite oldest entry
            currentLogIndex = (short)((currentLogIndex + 1) % MAX_TRANSACTIONS);
            logCount = MAX_TRANSACTIONS;
        } else {
            logCount++;
        }

        short logOffset = (short)(currentLogIndex * LOG_ENTRY_SIZE);

        // Store timestamp (simplified)
        byte[] timestamp = new byte[4];
        random.generateData(timestamp, (short)0, (short)4);
        Util.arrayCopy(timestamp, (short)0, transactionLog, logOffset, (short)4);

        // Store transaction amount (first 6 bytes of transactionData, assuming it's amount)
        short amountLen = (short)6;
        if (transactionData.length >= amountLen) {
            Util.arrayCopy(transactionData, (short)0, transactionLog, (short)(logOffset + 4), amountLen);
        }

        // Store cryptogram
        Util.arrayCopy(cryptogram, (short)0, transactionLog, (short)(logOffset + 10), (short)8);

        // Store signature presence flag
        transactionLog[(short)(logOffset + 18)] = (signature != null) ? (byte)1 : (byte)0;

        currentLogIndex = (short)((currentLogIndex + 1) % MAX_TRANSACTIONS);
    }

    // Test commands for GREENWIRE
    private void getLogCount(APDU apdu) {
        byte[] response = {(byte)logCount};
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)1);
        apdu.sendBytesLong(response, (short)0, (short)1);
    }

    private void getLogEntry(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte entryIndex = buffer[ISO7816.OFFSET_P1];

        if (entryIndex >= logCount) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        short logOffset = (short)(entryIndex * LOG_ENTRY_SIZE);
        apdu.setOutgoing();
        apdu.setOutgoingLength(LOG_ENTRY_SIZE);
        apdu.sendBytesLong(transactionLog, logOffset, LOG_ENTRY_SIZE);
    }

    private void clearLogs(APDU apdu) {
        Util.arrayFillNonAtomic(transactionLog, (short)0, (short)transactionLog.length, (byte)0);
        logCount = 0;
        currentLogIndex = 0;
    }

    private void forceDDA(APDU apdu) {
        useDDA = true;
        useCDA = false;
    }

    private void forceCDA(APDU apdu) {
        useDDA = false;
        useCDA = true;
    }
}