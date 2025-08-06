/*
 * JCOPCardManager communicates with JCOP-based smartcards using the
 * Java Smart Card I/O API (javax.smartcardio). Ensure a PC/SC service
 * and compatible reader driver are installed (e.g. pcscd and
 * libpcsclite on Linux) as well as JDK 17 or later.
 */
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class JCOPCardManager {
    private static final Logger logger = Logger.getLogger(JCOPCardManager.class.getName());

    private CardTerminal terminal;
    private Card card;
    private CardChannel channel;

    /**
     * Constructs a JCOPCardManager and selects the first available smartcard terminal.
     * If multiple terminals are present, the first one in the list is used.
     * 
     * @throws Exception if no smartcard terminals are found.
     */
    public JCOPCardManager() throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        if (terminals.isEmpty()) {
            throw new Exception("No smartcard terminals found.");
        }
        terminal = terminals.get(0);
    }

    /**
     * @throws CardException
     */
    public void connect() throws CardException {
        try {
            card = terminal.connect("T=1");
            channel = card.getBasicChannel();
            logger.log(Level.INFO, "Connected to card: {0}", card);
        } catch (CardException e) {
            logger.log(Level.SEVERE, "Connection failed: {0}", e.getMessage());
            throw new CardException("Connection failed", e);
        }
    }

    /**
     * Issues a card of the specified type with the given Logical Unit Number (LUN).
     * 
     * @param cardType the type of card to issue (e.g., "visa", "mastercard")
     * @param lun the Logical Unit Number as a 16-digit numeric string; if null or empty, a random 16-digit LUN will be generated
     * @throws Exception if issuing the card fails
     */
    public void issueCard(String cardType, String lun) throws Exception {
        if (lun == null || lun.isEmpty()) {
            lun = generateRandomLUN();
        }
        logger.log(Level.INFO, "Issuing {0} card with LUN: {1}", new Object[]{cardType, lun});
        byte[] lunBytes = lun.getBytes(StandardCharsets.UTF_8);
        byte[] apdu = new byte[5 + lunBytes.length];
        apdu[0] = 0x00;
        apdu[1] = (byte) 0xA4;
        apdu[2] = 0x04;
        apdu[3] = 0x00;
        apdu[4] = (byte) lunBytes.length;
        System.arraycopy(lunBytes, 0, apdu, 5, lunBytes.length);
        sendAPDU(apdu);
    }

    public void searchRootCA(String commandType) throws Exception {
        logger.log(Level.INFO, "Searching for root CA for {0}", commandType);
        byte[] apdu = new byte[]{0x00, (byte) 0xCA, 0x00, 0x00, 0x00};
        sendAPDU(apdu);
    }

    private void sendAPDU(byte[] apdu) throws CardException {
        if (apdu == null || apdu.length == 0) {
            throw new IllegalArgumentException("APDU cannot be null or empty");
        }
        if (channel == null) {
            throw new IllegalStateException("Card channel is not initialized. Call connect() first.");
        }
        try {
            CommandAPDU command = new CommandAPDU(apdu);
            ResponseAPDU response = channel.transmit(command);
            logger.log(Level.INFO, "Response: {0}", response);
        } catch (CardException | IllegalArgumentException e) {
            logger.log(Level.SEVERE, "Failed to send APDU: {0}", e.getMessage());
            throw new CardException("Failed to send APDU", e);
        }
    }

    public void disconnect() throws CardException {
        try {
            if (card != null) {
                card.disconnect(false);
                logger.log(Level.INFO, "Disconnected from card.");
            }
        } catch (CardException e) {
            logger.log(Level.SEVERE, "Disconnection failed: {0}", e.getMessage());
            throw new CardException("Disconnection failed", e);
        }
    }

    public static void main(String[] args) {
        try {
            JCOPCardManager manager = new JCOPCardManager();
            manager.connect();
            manager.issueCard("visa", null);
            manager.searchRootCA("DDA");
            manager.disconnect();
        } catch (Exception e) {
            JCOPCardManager.logger.log(Level.SEVERE, "Error: {0}", e.getMessage());
        }
    }
}
