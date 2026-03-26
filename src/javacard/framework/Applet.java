/*
 * GREENWIRE - Java Card compilation stub
 */
package javacard.framework;

/**
 * Stub for javacard.framework.Applet – base class for all Java Card applets.
 */
public abstract class Applet {

    protected Applet() {}

    /**
     * Called by the Java Card runtime to select this applet.
     */
    public boolean select() { return true; }

    /**
     * Called by the Java Card runtime to deselect this applet.
     */
    public void deselect() {}

    /**
     * Process an incoming APDU.
     *
     * @param apdu the incoming APDU
     */
    public abstract void process(APDU apdu) throws ISOException;

    /**
     * Register this applet with the default AID.
     */
    protected final void register() {}

    /**
     * Register this applet with the given AID.
     */
    protected final void register(byte[] bArray, short bOffset, byte bLength) {}

    /**
     * Utility: select this applet as the currently selected applet.
     */
    protected final boolean selectingApplet() { return true; }
}
