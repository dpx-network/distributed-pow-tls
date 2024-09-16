import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

public class Coordinator {
    private static final int PORT = 12345;
    private static final int EXPECTED_NODES = 5;
    private static final int DIFFICULTY = 4; // PoW difficulty
    private static final Logger logger = Logger.getLogger(Coordinator.class.getName());

    private SSLServerSocket serverSocket;
    private long combinedResult = 0;
    private int nodesProcessed = 0;

    // Thread pool to handle multiple node connections concurrently
    private ExecutorService executorService = Executors.newFixedThreadPool(EXPECTED_NODES);

    public Coordinator() throws Exception {
        setupSSL();
    }

    // Setup SSL context with KeyStore and TrustStore
    private void setupSSL() throws Exception {
        logger.info("Setting up SSL context for Coordinator.");

        // Load Coordinator’s KeyStore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("coordinator.jks"), "password".toCharArray());

        // Load Coordinator’s TrustStore
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream("coordinatorTrustStore.jks"), "password".toCharArray());

        // Initialize KeyManager and TrustManager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, "password".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);

        // Setup SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        // Create SSL Server Socket
        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(PORT);
        serverSocket.setNeedClientAuth(true); // Require client authentication
    }

    // Start the Coordinator server
    public void startServer() throws Exception {
        logger.info("Coordinator listening on port " + PORT);

        // Accept connections asynchronously
        while (nodesProcessed < EXPECTED_NODES) {
            SSLSocket socket = (SSLSocket) serverSocket.accept();
            nodesProcessed++;
            executorService.submit(() -> handleNodeConnection(socket));
        }

        // Shutdown executor service and close server socket
        executorService.shutdown();
        serverSocket.close();

        // Output the final aggregated result
        logger.info("All nodes processed. Combined Result: " + combinedResult);
    }

    // Handle node connection
    private void handleNodeConnection(SSLSocket socket) {
        try (DataInputStream input = new DataInputStream(socket.getInputStream())) {

            // Receive data from the node
            String nodeId = input.readUTF();
            String nodeResult = input.readUTF();
            String nodeSignature = input.readUTF();
            String nonce = input.readUTF();

            // Get the node’s certificate
            Certificate[] certs = socket.getSession().getPeerCertificates();
            PublicKey nodePublicKey = certs[0].getPublicKey();

            // Verify the signature
            boolean isSignatureValid = verifySignature(nodeResult, nodeSignature, nodePublicKey);

            // Verify the Proof of Work
            boolean isPoWValid = verifyProofOfWork(nodeResult, nonce, DIFFICULTY);

            if (isSignatureValid && isPoWValid) {
                logger.info("Node " + nodeId + ": Signature and Proof of Work verified successfully.");
                combinedResult += Long.parseLong(nodeResult);
            } else {
                logger.warning("Node " + nodeId + ": Verification failed. Discarding result.");
            }

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error handling node connection: ", e);
        }
    }

    // Verify the digital signature from a node
    private boolean verifySignature(String data, String signature, PublicKey publicKey) throws Exception {
        logger.info("Verifying signature.");
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(data.getBytes());

        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    // Verify the Proof of Work
    private boolean verifyProofOfWork(String data, String nonce, int difficulty) {
        String hash = sha256(data + nonce);
        String prefix = new String(new char[difficulty]).replace('\0', '0');
        return hash.startsWith(prefix);
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

    public static void main(String[] args) {
        try {
            Coordinator coordinator = new Coordinator();
            coordinator.startServer();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Coordinator encountered an error: ", e);
        }
    }
}
