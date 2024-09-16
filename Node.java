import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Random;
import java.util.logging.*;

public class Node {
    private final String nodeId;
    private final PrivateKey privateKey;
    private static final String COORDINATOR_HOST = "localhost";
    private static final int COORDINATOR_PORT = 12345;
    private static final int DIFFICULTY = 4; // PoW difficulty
    private static final Logger logger = Logger.getLogger(Node.class.getName());

    private SSLSocket socket;

    public Node(String nodeId) throws Exception {
        this.nodeId = nodeId;
        this.privateKey = loadPrivateKey();
        setupSSL();
    }

    // Load Node’s private key from KeyStore
    private PrivateKey loadPrivateKey() throws Exception {
        logger.info("Node " + nodeId + ": Loading private key.");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("node.jks"), "password".toCharArray());

        Key key = keyStore.getKey("node", "password".toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        } else {
            throw new Exception("Private key not found in KeyStore.");
        }
    }

    // Setup SSL context
    private void setupSSL() throws Exception {
        logger.info("Node " + nodeId + ": Setting up SSL context.");

        // Load Node’s KeyStore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("node.jks"), "password".toCharArray());

        // Load Node’s TrustStore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream("nodeTrustStore.jks"), "password".toCharArray());

        // Initialize KeyManager and TrustManager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, "password".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);

        // Setup SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // Create SSL Socket
        SSLSocketFactory ssf = sslContext.getSocketFactory();
        socket = (SSLSocket) ssf.createSocket(COORDINATOR_HOST, COORDINATOR_PORT);
        socket.startHandshake();
    }

    // Send the result and signature to the Coordinator
    public void sendResultToCoordinator() {
        try (DataOutputStream output = new DataOutputStream(socket.getOutputStream())) {

            long computationResult = computeTask();
            String resultString = Long.toString(computationResult);

            // Perform Proof of Work
            String nonce = performProofOfWork(resultString, DIFFICULTY);

            // Sign the result
            String signedResult = signData(resultString, privateKey);

            // Send the node ID, result, signature, and nonce to the Coordinator
            output.writeUTF(nodeId);
            output.writeUTF(resultString);
            output.writeUTF(signedResult);
            output.writeUTF(nonce);

            logger.info("Node " + nodeId + ": Data sent to Coordinator.");

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Node " + nodeId + ": Error sending data to Coordinator: ", e);
        }
    }

    // Sign data using the private key
    private String signData(String data, PrivateKey privateKey) throws Exception {
        logger.info("Node " + nodeId + ": Signing data.");
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(data.getBytes());

        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    // Perform Proof of Work
    private String performProofOfWork(String data, int difficulty) {
        logger.info("Node " + nodeId + ": Starting Proof of Work.");
        String nonce = "";
        String hash = "";
        String prefix = new String(new char[difficulty]).replace('\0', '0');
        int nonceInt = 0;

        while (true) {
            nonce = Integer.toString(nonceInt);
            hash = sha256(data + nonce);
            if (hash.startsWith(prefix)) {
                logger.info("Node " + nodeId + ": Proof of Work completed. Nonce: " + nonce);
                break;
            }
            nonceInt++;
        }
        return nonce;
    }

    // Compute SHA-256 hash
    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes());
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            logger.severe("SHA-256 algorithm not found.");
            return null;
        }
    }

    // Convert bytes to hex string
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Simulate a CPU-heavy task (computation)
    private long computeTask() {
        logger.info("Node " + nodeId + ": Performing computation...");
        long result = 0;
        for (long i = 0; i < 10000000; i++) {
            result += i % 7; // Arbitrary CPU-heavy task
        }
        logger.info("Node " + nodeId + ": Computation finished. Result: " + result);
        return result;
    }

    public static void main(String[] args) {
        try {
            // Node ID can be passed as a command-line argument
            String nodeId = args.length > 0 ? args[0] : "Node" + new Random().nextInt(1000);
            Node node = new Node(nodeId);
            node.sendResultToCoordinator();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Node encountered an error: ", e);
        }
    }
}
