import javax.smartcardio.*;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

public class JCOPCardManager {
    private static final Logger logger = Logger.getLogger(JCOPCardManager.class.getName());

    private CardTerminal terminal;
    private Card card;
    private CardChannel channel;

    public JCOPCardManager() throws Exception {
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        if (terminals.isEmpty()) {
            throw new Exception("No smartcard terminals found.");
        }
        terminal = terminals.get(0);
    }

    public void connect() throws CardException {
        try {
            card = terminal.connect("T=1");
            channel = card.getBasicChannel();
            logger.info("Connected to card: " + card);
        } catch (CardException e) {
            logger.severe("Connection failed: " + e.getMessage());
            throw new CardException("Connection failed", e);
        }
    }

    public void issueCard(String cardType, String lun) throws Exception {
        if (lun == null || lun.isEmpty()) {
            lun = generateRandomLUN();
        }
        logger.info("Issuing " + cardType + " card with LUN: " + lun);
        byte[] apdu = new byte[]{0x00, (byte) 0xA4, 0x04, 0x00, (byte) lun.length()};
        System.arraycopy(lun.getBytes(), 0, apdu, 5, lun.length());
        sendAPDU(apdu);
    }

    public void searchRootCA(String commandType) throws Exception {
        logger.info("Searching for root CA for " + commandType);
        byte[] apdu = new byte[]{0x00, (byte) 0xCA, 0x00, 0x00, 0x00};
        sendAPDU(apdu);
    }

    private void sendAPDU(byte[] apdu) throws CardException {
        if (apdu == null || apdu.length == 0) {
            throw new IllegalArgumentException("APDU cannot be null or empty");
        }
        try {
            CommandAPDU command = new CommandAPDU(apdu);
            ResponseAPDU response = channel.transmit(command);
            logger.info("Response: " + response.toString());
        } catch (Exception e) {
            logger.severe("Failed to send APDU: " + e.getMessage());
            throw new CardException("Failed to send APDU", e);
        }
    }

    private String generateRandomLUN() {
        Random random = new Random();
        StringBuilder lun = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            lun.append(random.nextInt(10));
        }
        return lun.toString();
    }

    public void disconnect() throws CardException {
        try {
            if (card != null) {
                card.disconnect(false);
                logger.info("Disconnected from card.");
            }
        } catch (CardException e) {
            logger.severe("Disconnection failed: " + e.getMessage());
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
            logger.severe("Error: " + e.getMessage());
        }
    }
}
