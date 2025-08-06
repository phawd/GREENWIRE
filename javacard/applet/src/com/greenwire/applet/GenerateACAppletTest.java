package com.greenwire.applet;

import javacard.framework.*;
import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class GenerateACAppletTest {

    private GenerateACApplet applet;
    private APDU mockApdu;
    private byte[] buffer;

    @Before
    public void setUp() {
        applet = mock(GenerateACApplet.class, CALLS_REAL_METHODS);
        mockApdu = mock(APDU.class);
        buffer = new byte[5];
        when(mockApdu.getBuffer()).thenReturn(buffer);
    }

    @Test
    public void testInstall() {
        // Should not throw any exception
        GenerateACApplet.install(new byte[0], (short)0, (byte)0);
    }

    @Test
    public void testProcessGenerateAC() {
        buffer[ISO7816.OFFSET_INS] = (byte) 0xAE;
        when(mockApdu.getBuffer()).thenReturn(buffer);

        // Simulate not selecting applet
        when(applet.selectingApplet()).thenReturn(false);

        // Spy to verify outgoing send
        doNothing().when(mockApdu).setOutgoingAndSend(anyShort(), anyShort());

        applet.process(mockApdu);

        // The cryptogram should be written to buffer
        assertEquals((byte)0xDE, buffer[0]);
        assertEquals((byte)0xAD, buffer[1]);
        assertEquals((byte)0xBE, buffer[2]);
        assertEquals((byte)0xEF, buffer[3]);
        verify(mockApdu).setOutgoingAndSend((short)0, (short)4);
    }

    @Test(expected = ISOException.class)
    public void testProcessUnsupportedInstruction() {
        buffer[ISO7816.OFFSET_INS] = (byte) 0x00; // Not 0xAE
        when(mockApdu.getBuffer()).thenReturn(buffer);
        when(applet.selectingApplet()).thenReturn(false);

        applet.process(mockApdu);
    }

    @Test
    public void testProcessSelectingApplet() {
        when(applet.selectingApplet()).thenReturn(true);
        // Should return immediately, not throw
        applet.process(mockApdu);
    }
}
