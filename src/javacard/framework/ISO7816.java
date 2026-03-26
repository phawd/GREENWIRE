/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.ISO7816 – ISO 7816 constants.
 */
public interface ISO7816 {

    /* APDU instruction bytes */
    byte INS_SELECT         = (byte) 0xA4;
    byte INS_EXTERNAL_AUTH  = (byte) 0x82;
    byte INS_GET_CHALLENGE  = (byte) 0x84;
    byte INS_INTERNAL_AUTH  = (byte) 0x88;
    byte INS_READ_RECORD    = (byte) 0xB2;
    byte INS_GET_RESPONSE   = (byte) 0xC0;
    byte INS_ENVELOPE       = (byte) 0xC2;
    byte INS_GET_DATA       = (byte) 0xCA;
    byte INS_PUT_DATA       = (byte) 0xDA;
    byte INS_VERIFY         = (byte) 0x20;
    byte INS_CHANGE_CHV     = (byte) 0x24;
    byte INS_DISABLE_CHV    = (byte) 0x26;
    byte INS_ENABLE_CHV     = (byte) 0x28;
    byte INS_UNBLOCK_CHV    = (byte) 0x2C;
    byte INS_GENERATE_KEYPAIR = (byte) 0x46;

    /* Status words */
    short SW_NO_ERROR                      = (short) 0x9000;
    short SW_BYTES_REMAINING_00            = (short) 0x6100;
    short SW_WRONG_LENGTH                  = (short) 0x6700;
    short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;
    short SW_FILE_INVALID                  = (short) 0x6983;
    short SW_DATA_INVALID                  = (short) 0x6984;
    short SW_CONDITIONS_NOT_SATISFIED      = (short) 0x6985;
    short SW_COMMAND_NOT_ALLOWED           = (short) 0x6986;
    short SW_APPLET_SELECT_FAILED          = (short) 0x6999;
    short SW_WRONG_DATA                    = (short) 0x6A80;
    short SW_FUNC_NOT_SUPPORTED            = (short) 0x6A81;
    short SW_FILE_NOT_FOUND                = (short) 0x6A82;
    short SW_RECORD_NOT_FOUND              = (short) 0x6A83;
    short SW_INCORRECT_P1P2                = (short) 0x6A86;
    short SW_REFERENCED_DATA_NOT_FOUND     = (short) 0x6A88;
    short SW_WRONG_P1P2                    = (short) 0x6B00;
    short SW_CORRECT_LENGTH_00             = (short) 0x6C00;
    short SW_INS_NOT_SUPPORTED             = (short) 0x6D00;
    short SW_CLA_NOT_SUPPORTED             = (short) 0x6E00;
    short SW_UNKNOWN                       = (short) 0x6F00;
    short SW_FILE_FULL                     = (short) 0x6A84;
    short SW_LOGICAL_CHANNEL_NOT_SUPPORTED = (short) 0x6881;
    short SW_SECURE_MESSAGING_NOT_SUPPORTED = (short) 0x6882;
    short SW_WARNING_STATE_UNCHANGED       = (short) 0x6200;
    short SW_PIN_TRIES_REMAINING           = (short) 0x63C0;
    short SW_LAST_COMMAND_IN_CHAIN         = (short) 0x6600;

    /* Offset constants */
    byte OFFSET_CLA  = 0;
    byte OFFSET_INS  = 1;
    byte OFFSET_P1   = 2;
    byte OFFSET_P2   = 3;
    byte OFFSET_LC   = 4;
    byte OFFSET_CDATA = 5;
    byte OFFSET_EXT_CDATA = 7;

    /* CLA values */
    byte CLA_ISO7816 = (byte) 0x00;
}
