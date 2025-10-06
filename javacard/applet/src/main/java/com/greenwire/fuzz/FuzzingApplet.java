package com.greenwire.fuzz;

import javacard.framework.*;

/**
 * GREENWIRE Fuzzing Test Applet
 * 
 * This applet provides controlled vulnerabilities and behaviors for testing
 * the GREENWIRE fuzzing framework. It implements various test cases including:
 * - Buffer handling edge cases
 * - Timing variations
 * - State machine testing
 * - Custom instruction handling
 */
public class FuzzingApplet extends Applet {
    
    // Test AID for fuzzing: A0000006230146555A5A
    private static final byte[] FUZZING_AID = {
        (byte)0xA0, 0x00, 0x00, 0x06, 0x23, 0x01, 0x46, 0x55, 0x5A, 0x5A
    };
    
    // State tracking
    private short counter = 0;
    private byte currentState = 0;
    private byte[] sessionData = new byte[256];
    private short sessionDataLength = 0;
    
    // Test flags
    private static final byte STATE_INIT = 0x00;
    private static final byte STATE_AUTHENTICATED = 0x01;
    private static final byte STATE_LOCKED = 0x02;
    
    // Custom instructions for testing
    private static final byte INS_GET_DATA = (byte)0x00;
    private static final byte INS_PUT_DATA = (byte)0x01;
    private static final byte INS_AUTHENTICATE = (byte)0x88;
    private static final byte INS_TIMING_TEST = (byte)0xF0;
    private static final byte INS_BUFFER_TEST = (byte)0xF1;
    private static final byte INS_STATE_TEST = (byte)0xF2;
    private static final byte INS_RESET_STATE = (byte)0xFF;
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FuzzingApplet().register();
    }
    
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return; // Return success for SELECT
        }
        
        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];
        
        // Increment counter for all commands
        counter++;
        
        switch (ins) {
            case INS_GET_DATA:
                handleGetData(apdu, p1, p2);
                break;
            case INS_PUT_DATA:
                handlePutData(apdu);
                break;
            case INS_AUTHENTICATE:
                handleAuthenticate(apdu, p1, p2);
                break;
            case INS_TIMING_TEST:
                handleTimingTest(apdu, p1);
                break;
            case INS_BUFFER_TEST:
                handleBufferTest(apdu);
                break;
            case INS_STATE_TEST:
                handleStateTest(apdu, p1);
                break;
            case INS_RESET_STATE:
                handleResetState(apdu);
                break;
            default:
                // Unknown instruction - test fuzzer's handling of errors
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    /**
     * Handle GET DATA command - returns various test data
     */
    private void handleGetData(APDU apdu, byte p1, byte p2) {
        byte[] buf = apdu.getBuffer();
        short responseLength = 0;
        
        switch (p1) {
            case 0x00: // Return counter
                buf[0] = (byte)(counter >> 8);
                buf[1] = (byte)(counter & 0xFF);
                responseLength = 2;
                break;
            case 0x01: // Return current state
                buf[0] = currentState;
                responseLength = 1;
                break;
            case 0x02: // Return session data
                if (sessionDataLength > 0) {
                    Util.arrayCopyNonAtomic(sessionData, (short)0, buf, (short)0, sessionDataLength);
                    responseLength = sessionDataLength;
                } else {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                break;
            case 0x03: // Return AID
                Util.arrayCopyNonAtomic(FUZZING_AID, (short)0, buf, (short)0, (short)FUZZING_AID.length);
                responseLength = (short)FUZZING_AID.length;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        
        apdu.setOutgoingAndSend((short)0, responseLength);
    }
    
    /**
     * Handle PUT DATA command - stores data in session buffer
     */
    private void handlePutData(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        
        // Test buffer overflow protection
        if (lc > sessionData.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        // Copy data to session buffer
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, sessionData, (short)0, lc);
        sessionDataLength = lc;
        
        // Return success
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
    
    /**
     * Handle authentication - simple PIN verification
     */
    private void handleAuthenticate(APDU apdu, byte p1, byte p2) {
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        
        // Simple PIN: 1234 (for testing purposes)
        byte[] testPin = {0x31, 0x32, 0x33, 0x34}; // "1234"
        
        if (lc != testPin.length) {
            currentState = STATE_LOCKED;
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        
        // Compare PIN
        if (Util.arrayCompare(buf, ISO7816.OFFSET_CDATA, testPin, (short)0, (short)testPin.length) == 0) {
            currentState = STATE_AUTHENTICATED;
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
        } else {
            currentState = STATE_LOCKED;
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }
    
    /**
     * Handle timing test - intentional delays for fuzzer detection
     */
    private void handleTimingTest(APDU apdu, byte p1) {
        // Create variable timing based on P1 parameter
        short delayCount = (short)(p1 * 100);
        
        // Artificial processing delay
        for (short i = 0; i < delayCount; i++) {
            counter++; // Simple operation to consume cycles
        }
        
        byte[] buf = apdu.getBuffer();
        buf[0] = p1; // Echo the delay parameter
        buf[1] = (byte)(delayCount >> 8);
        buf[2] = (byte)(delayCount & 0xFF);
        
        apdu.setOutgoingAndSend((short)0, (short)3);
    }
    
    /**
     * Handle buffer test - test various buffer sizes
     */
    private void handleBufferTest(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short lc = apdu.setIncomingAndReceive();
        
        // Test different responses based on input length
        if (lc == 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        } else if (lc > 128) {
            // Simulate buffer overflow protection
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        } else {
            // Echo back the received data
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, lc);
        }
    }
    
    /**
     * Handle state test - test state machine behavior
     */
    private void handleStateTest(APDU apdu, byte p1) {
        byte[] buf = apdu.getBuffer();
        
        // State-dependent behavior
        switch (currentState) {
            case STATE_INIT:
                if (p1 == 0x01) {
                    currentState = STATE_AUTHENTICATED;
                    buf[0] = (byte)0x01; // Success
                } else {
                    buf[0] = (byte)0x00; // Failed
                }
                break;
            case STATE_AUTHENTICATED:
                if (p1 == 0x02) {
                    // Perform privileged operation
                    buf[0] = (byte)0x02; // Privileged success
                } else {
                    buf[0] = (byte)0x01; // Normal operation
                }
                break;
            case STATE_LOCKED:
                // All operations fail in locked state
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                break;
        }
        
        apdu.setOutgoingAndSend((short)0, (short)1);
    }
    
    /**
     * Reset applet state
     */
    private void handleResetState(APDU apdu) {
        currentState = STATE_INIT;
        counter = 0;
        sessionDataLength = 0;
        
        // Clear session data
        Util.arrayFillNonAtomic(sessionData, (short)0, (short)sessionData.length, (byte)0x00);
        
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
}