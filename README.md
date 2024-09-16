# Distributed Proof-of-Work System with TLS Encryption

This project implements a distributed system for performing Proof of Work (PoW) in a secure environment using TLS encryption for communication between a central Coordinator and multiple Nodes.

## Features
- **TLS Encryption**: Secure communication using SSL/TLS between Coordinator and Nodes.
- **Mutual Authentication**: Both Coordinator and Nodes verify each other's certificates.
- **Proof of Work (PoW)**: Each Node performs a computation-heavy task, and the result is verified for correctness.
- **Signature Verification**: Results from the Nodes are digitally signed and verified by the Coordinator.
- **Scalability**: Coordinator uses a thread pool to handle multiple node connections concurrently.

## Setup

### Prerequisites
- **Java Development Kit (JDK)** (version 8 or above)
- **Keytool**: Part of the JDK to generate certificates for mutual authentication.

### Generate Certificates

1. **Generate Coordinator KeyStore**:
    ```bash
    keytool -genkeypair -alias coordinator -keyalg RSA -keysize 2048 -storetype JKS -keystore coordinator.jks -validity 3650
    ```

2. **Generate Node KeyStore**:
    ```bash
    keytool -genkeypair -alias node -keyalg RSA -keysize 2048 -storetype JKS -keystore node.jks -validity 3650
    ```

3. **Export Coordinator Certificate**:
    ```bash
    keytool -export -alias coordinator -keystore coordinator.jks -file coordinator.crt
    ```

4. **Import Coordinator Certificate into Node TrustStore**:
    ```bash
    keytool -import -alias coordinator -file coordinator.crt -keystore nodeTrustStore.jks
    ```

### Compile the Code

1. **Compile the Coordinator and Node classes**:
    ```bash
    javac Coordinator.java
    javac Node.java
    ```

### Run the System

1. **Start the Coordinator**:
    ```bash
    java Coordinator
    ```

2. **Start Multiple Nodes** (in separate terminal windows):
    ```bash
    java Node Node1
    java Node Node2
    java Node Node3
    java Node Node4
    java Node Node5
    ```

3. **Observe the Output**:
    The Coordinator will display logs indicating successful connections, verification, and the combined result.
    Each Node will log its computation, Proof of Work completion, and data transmission.

## Future Enhancements
- Implement Asynchronous I/O using Java NIO for non-blocking network communication.
- Transition to a fully decentralized network architecture with Peer-to-Peer communication.

## License
This project is licensed under the MIT License.
