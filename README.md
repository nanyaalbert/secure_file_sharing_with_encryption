# Secure File Sharing System (Java NIO & Hybrid Encryption)
A high-performance, cryptographically secure file sharing application built in Java. This project implements a custom protocol to facilitate secure file uploads, downloads, and directory listing using a sophisticated Hybrid Encryption model.

## Security Architecture
This system implements a multi-layered security stack to ensure Confidentiality, Integrity, and Authenticity (CIA).

1. **The Secure Handshake**  
The connection begins with a cryptographic handshake to establish a shared secret without ever transmitting the final key:

    - **Asymmetric Identity Layer:** 2048-bit RSA with OAEP padding is used for the initial secure exchange of public keys.

    - **Key Agreement (ECDH):** The system utilizes Elliptic Curve Diffie-Hellman (secp256r1) to derive a shared secret. This provides Forward Secrecy, as session keys are unique to each connection.

    - **Key Derivation:** The derived secret is hashed using SHA-256 to create a 256-bit AES session key.

2. **Authenticated Data Transfer**  
The protocol uses a dual-encryption strategy to manage control signals and data streaming:

    - **RSA-OAEP Control Blocks:** Commands and metadata (such as the length of the upcoming payload) are encrypted using RSA-OAEP with a specific OAEPParameterSpec (SHA-256/MGF1). This ensures that control signals are always contained in predictable 256-byte blocks, allowing the receiver to precisely read and decrypt metadata to know exactly what to expect in the following stream.

    - **AES-256-GCM Data Streaming:** Once a command is interpreted via RSA, the bulk response or file data is processed using AES-256-GCM (Galois/Counter Mode) for high-speed, authenticated streaming.

    - **AAD (Additional Authenticated Data):** The implementation explicitly calls updateAAD(additionalDataBytes) before finalizing the cipher. This binds session-specific metadata to the encryption process, ensuring that ciphertext cannot be intercepted and injected into a different context or session without triggering an authentication failure.

    - **Stateful Replay Protection:** A custom IV (Initialization Vector) Counter system is synchronized between the client and server. The IV for each operation is modified by a long counter that increments with every doFinal() call. This ensures that every single packet uses a unique IV, preventing attackers from re-injecting captured packets into the stream.

3. **Anti-Forensic Memory Safety**  
Implements active memory sanitization to protect sensitive credentials

    - **Secure Password Handling:** Instead of using immutable String objects for passwords, the system utilizes CharBuffer. This allows for the password to be captured, processed, and immediately zeroed out (Arrays.fill) in memory.

    - **Buffer Sanitization:** Immediately after processing cryptographic keys or sensitive buffers, the system explicitly overwrites ByteBuffers with zeros before they are released.

## Technical Implementation  
### Non-Blocking & Asynchronous I/O  
The project leverages the full power of Java's java.nio package to ensure maximum throughput:  
- **Network NIO:** Uses SocketChannel and Selector to handle multiple clients on a single thread without blocking.
- **Disk Asynchrony:** Implements AsynchronousFileChannel with CompletionHandler. This allows the server to read/write files to the disk in the background, notifying the system only when the operation is complete.

- **Zero-Copy Principles:** Utilizes DirectBuffers to move data directly between the disk and network interface, bypassing unnecessary memory copies.

### Server State Management
The server manages client connections through a Finite State Machine (FSM). Each ClientSession tracks its current ProgressState:

- **Handshake States:** Tracking the transition from RSA key exchange to ECDH secret derivation.

- **Command States:** Managing the transition between waiting for a command (LIST, UPLOAD, DOWNLOAD) and actively streaming file data.

- **Cleanup:** Automatic state reset and buffer wiping upon command completion or unexpected disconnection.

### Graceful Termination
- **Shutdown Hooks:** Implements Runtime.getRuntime().addShutdownHook() to ensure that if the client is closed abruptly, it attempts to send an encrypted EXIT signal to the server and securely wipes sensitive keys from memory.

### Custom Terminal Handling
- **Manual Password Masking:** Implements a Scanner-based overwrite technique to keep passwords hidden after typing, avoiding the pitfalls of System.console() in certain environments.

- **ANSI Progress Bars:** Uses ANSI Escape Codes and Carriage Returns (\r) for smooth, flicker-free progress bars.

## Setup and Configuration
This project uses **Public Key Pinning** for maximum security. Before compiling, you must generate your own RSA identity keys.
### Generate RSA Identity  
Run the `RSAKeyGenerator` utility to generate a new 2048-bit RSA key pair:

```bash
java RSAKeyGenerator
```

The utility will output two Base64-encoded strings: your Public Key and your Private Key.

### Configure the Server  
Open SecureFileSharingServerWithEncryption.java and locate the hardcoded key variables at the top of the class. Replace them with your generated strings:

```java
private static final byte[] ENCODED_RSA_PUBLIC_KEY_BYTES = "YOUR_GENERATED_PUBLIC_KEY".getBytes(StandardCharsets.UTF_8);

private static final byte[] ENCODED_RSA_PRIVATE_KEY_BYTES = "YOUR_GENERATED_PRIVATE_KEY".getBytes(StandardCharsets.UTF_8);
```

### Configure the Client  
Open SecureFileSharingClientWithEncryption.java. To ensure the client only connects to your server, paste the Server's Public Key here:

```java
private static final byte[] ENCODED_SERVER_RSA_PUBLIC_KEY_BYTES = "YOUR_GENERATED_PUBLIC_KEY".getBytes(StandardCharsets.UTF_8);
```

### Compilation and Packaging  
Once the keys are swapped, compile the source:

```bash
javac *.java
```

#### Package the Server
Package only Server-related files

```bash
jar cvfm SecureServer.jar server-manifest.txt SecureFileSharingServerWithEncryption*.class
```

#### Package the Client
Package only Server-related files

```bash
jar cvfm SecureClient.jar client-manifest.txt SecureFileSharingClientWithEncryption*.class
```

#### Deployment
| If running the... | Transfer this file | Run Command |
| :--- | :--- | :--- |
| **SERVER** | SecureServer.jar | ```java -jar SecureServer.jar``` |
| **CLIENT** | SecureClient.jar | ```java -jar SecureClient.jar``` |

##### Required Inputs for Client:

- **Server IP:** Use the Local IP for LAN (e.g., 192.168.x.x) or Public IP for WAN.
- **Password:** Enter the server password (input is masked for security).

## Networking Notes
### Local Area Network (LAN)
The system is fully functional on local networks without internet. Ensure both devices are on the same router/subnet and use the server's local IP.

### Over the Internet (WAN)
You must Port Forward TCP port 1234 in your router settings to the Server's local IP to allow external connections.

### Security Warning:
NEVER give a Client user the SecureServer.jar or the server .java files

## Commands
| Command | Description |
| :--- | :--- |
| ```LIST``` | List all files in the server's directory. |
| ```UPLOAD <path>``` | Securely upload a local file to the server. |
| ```DOWNLOAD <name>``` | Securely download a file from the server. |
| ```EXIT``` | Securely wipe buffers and terminate the session. |