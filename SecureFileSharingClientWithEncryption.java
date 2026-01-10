import java.io.Console;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public class SecureFileSharingClientWithEncryption {
    private static final int PORT = 1234;
    private static final int EXIT = -1;
    private static final int NO_COMMAND = 0;
    private static final int FILE_SEND_REQUEST = 1;
    private static final int FILE_UPLOAD_REQUEST = 2;
    private static final int FILE_DOWNLOAD = 3;
    private static final int FILE_LIST_REQUEST = 4;
    private static final int FILE_LIST = 5;
    private static final int INFORMATION = 6;
    private static long TEMPFILENUMBER = 0;
    private static Path clientDownloadPath = Paths.get(System.getProperty("user.home"),
            "SecureFileSharingClientWithEncryption");
    private static Path clientTempPath = Paths.get(System.getProperty("java.io.tmpdir"),
            "SecureFileSharingClientWithEncryptionTemp");
    private static String serverIPAdress;

    private static Scanner userInput = new Scanner(System.in);

    private static char[] passwordChars;
    private static char[] passwordHandShakeChars;
    private static byte[] passwordHandShakeBytes;

    private enum Progress {
        JUST_CONNECTED,
        READY_TO_READ_HANDSHAKE,
        READING_FILEDATA,
        READING_FILEDETAILS,
        READING_INFORMATION,
        READING_HANDSHAKE,
        READING_FILELIST,
        WRITING_FILEDATA,
        WRITING_FILEDETAILS,
        WRITING_HANDSHAKE,
        VALID_HANDSHAKE
    }

    private enum ChunkProgress {
        DEFAULT,
        SENDING_CHUNK,
        CHUNK_SENT,
        ALL_CHUNK_SENT,
        RECEIVING_CHUNK,
        CHUNK_RECEIVED,
        WRITING_CHUNK_TO_FILE,
        CHUNK_WRITTEN_TO_FILE,
        ALL_CHUNK_WRITTEN_TO_FILE
    }

    private static InetSocketAddress serverAddress;

    private static RSAPublicKey clientRSAPublicKey;
    private static RSAPrivateKey clientRSAPrivateKey;
    private static ECPublicKey clientECPublicKey;
    private static ECPrivateKey clientECPrivateKey;
    private static final byte[] ENCODED_SERVER_RSA_PUBLIC_KEY_BYTES = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+TEpsZJxq1bDlcGsy4a//RRq3MMfYeE+1J6yL9LiqCf0hbdBE4y86sQjbUquoYi6VpTITiw7uzMg3wzRmkqABFtcbOtzNEeHSpqgMv88YRDlPbVutsE4JAxmm6BkA2cLqIgjM6jbZRrnR5kwaw/jWFmhOpazNRH/c6HWQ3KLFAUc/ZXBchm69gFOdtGJ939rzE9zzpLo5t+lp/kAbXbdug98Geo7Nky5A3rv3ooFAaRgwovCCKQWoKGFKndgk1TootJuLBH+DaeQ+sjDhlAByrygwuV9pPS31r1lYoWQ8Ls5RclfVIDxJLpmOxjx0x1Qn6ixnQ7P75Uy6rA9s3PiwIDAQAB"
            .getBytes(StandardCharsets.UTF_8);
    private static RSAPublicKey serverRSAPublicKey;
    private static ECPublicKey serverECPublicKey;

    private static ServerSession serverSession = null;
    private static SocketChannel socketChannel = null;

    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[EXIT] Shutting down client...");
            sendExitMessageToServer();
            exitApplication(false); // false flag to let the method know that this call was from the shutdown hook
                                    // and not the user selecting EXIT
        }));
        try {
            byte[] decodedServerRSAPublicKeyBytes = Base64.getDecoder().decode(ENCODED_SERVER_RSA_PUBLIC_KEY_BYTES);
            serverRSAPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(decodedServerRSAPublicKeyBytes));
            // secure wipe of ENCODED_SERVER_RSA_PUBLIC_KEY_BYTES, and
            // decodedServerRSAPublicKeyBytes
            Arrays.fill(ENCODED_SERVER_RSA_PUBLIC_KEY_BYTES, (byte) 0);
            Arrays.fill(decodedServerRSAPublicKeyBytes, (byte) 0);
        } catch (Exception e) {
            System.err.println("An error occured when loading the server public key: " + e.getMessage());
            return;
        }
        // Generate RSA key pairs for client
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            clientRSAPublicKey = (RSAPublicKey) kp.getPublic();
            clientRSAPrivateKey = (RSAPrivateKey) kp.getPrivate();
        } catch (Exception e) {
            System.out.println(
                    "An error occured when generating the client rsapublic and private key: " + e.getMessage());
            return;
        }
        // Generate ECDH key pairs for client
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            kpg.initialize(ecSpec);
            KeyPair kp = kpg.generateKeyPair();
            clientECPublicKey = (ECPublicKey) kp.getPublic();
            clientECPrivateKey = (ECPrivateKey) kp.getPrivate();
        } catch (Exception e) {
            System.out.println(
                    "An error occured when generating the client ecdh public and private key: " + e.getMessage());
            return;
        }
        // Create the necessary directories if they don't exist
        if (Files.notExists(clientDownloadPath)) {
            try {
                Files.createDirectories(clientDownloadPath);
            } catch (IOException e) {
                System.err.println("An error occured when creating the download directory: " + e.getMessage());
                return;
            }
        }
        if (Files.notExists(clientTempPath)) {
            try {
                Files.createDirectories(clientTempPath);
            } catch (IOException e) {
                System.err.println("An error occured when creating temp directory: " + e.getMessage());
                return;
            }
        }

        client();
    }

    private static void client() {
        System.out.println("==========================================================");
        System.out.println("    SECURE FILE SHARING WITH ENCRYPTION");
        System.out.println("==========================================================");

        System.out.println("Enter server IP or hostname: ");
        serverIPAdress = userInput.nextLine();

        System.out.println("Enter server password: ");
        passwordChars = userInput.nextLine().toCharArray();

        // \033[1A -> Move cursor UP one line
        // \r -> Move cursor to START of that line
        System.out.print("\033[1A\r");
        for (int i = 0; i < passwordChars.length; i++) {
            System.out.print("*");
        }
        System.out.println();

        // trying to avoid creating new string into the string pool
        passwordHandShakeChars = new char["SecureFileSharingHandShake".length() + passwordChars.length];
        System.arraycopy("SecureFileSharingHandShake".toCharArray(), 0, passwordHandShakeChars, 0,
                "SecureFileSharingHandShake".length());
        System.arraycopy(passwordChars, 0, passwordHandShakeChars, "SecureFileSharingHandShake".length(),
                passwordChars.length);
        passwordHandShakeBytes = StandardCharsets.UTF_8.encode(CharBuffer.wrap(passwordHandShakeChars)).array();

        serverAddress = new InetSocketAddress(serverIPAdress, PORT);
        try {
            socketChannel = SocketChannel.open();
            socketChannel.configureBlocking(true);
            System.out.println("Connecting to server...");
            socketChannel.connect(serverAddress);
            if (socketChannel.isConnected()) {
                System.out.println("Connected to server successfully...");
                System.out.println("Authenticating server...");
                serverSession = new ServerSession();
                writeHandShake(socketChannel, serverSession);
                readHandShake(socketChannel, serverSession);
                displayMainMenu(socketChannel, serverSession);
            } else {
                System.out.println("Failed to connect to server.");
                return;
            }

        } catch (Exception e) {
            System.err.println("An error occured: " + e.getMessage());
            return;
        }
    }

    private static void displayMainMenu(SocketChannel socketChannel, ServerSession serverSession) throws IOException {
        System.out.println();
        System.out.println("==========================================================");
        System.out.println("    SECURE FILE SHARING WITH ENCRYPTION");
        System.out.println("==========================================================");
        System.out.println("Connected to: " + serverAddress);
        System.out.println("Authentication successful...");
        System.out.println("----------------------------------------------------------");
        System.out.println();
        System.out.println("Please select an action:");
        System.out.println();
        System.out.println("[1] LIST     - View all available files on the server.");
        System.out.println("[2] UPLOAD   - Send a file.");
        System.out.println("               Usage: UPLOAD <local_file_path>");
        System.out.println("[3] DOWNLOAD - Retrieve a file.");
        System.out.println("               Usage: DOWNLOAD <remote_file_name>");
        System.out.println("[4] EXIT     - Exit application.");
        System.out.println();
        String userRequest;

        System.out.print("Enter command: ");
        userRequest = userInput.nextLine().trim();

        String[] parts = userRequest.split(" ", 2);
        String command = parts[0].trim().toUpperCase();
        String argument = parts.length > 1 ? parts[1].trim() : "";

        long bytesWritten;

        switch (command) {
            case "LIST" -> {
                serverSession.commandSendBuffer.clear().putInt(FILE_LIST_REQUEST).flip();
                try {
                    serverSession.encCommandSendBuffer = ByteBuffer
                            .wrap(serverSession.rsaEncrypt(serverSession.commandSendBuffer.array()));
                } catch (Exception e) {
                    System.out.println("An error occured while encrypting the command.");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
                while (serverSession.encCommandSendBuffer.position() < serverSession.encCommandSendBuffer.capacity()) {
                    try {
                        bytesWritten = socketChannel.write(serverSession.encCommandSendBuffer);
                        if (bytesWritten < 0) {
                            System.err.println("Server closed the connection");
                            cleanUpServerSessionObj(serverSession);
                            return;
                        }
                    } catch (Exception e) {
                        System.err.println("An error occured while writing command to server.");
                        exitApplication(true);
                        return;
                    }
                }
                clientReceiveFileList(socketChannel, serverSession);

            }
            case "UPLOAD" -> {
                serverSession.fileToSend = Paths.get(argument);
                if (!Files.exists(serverSession.fileToSend)) {
                    System.err.println("File does not exist, please check the file path");
                    resetServerSessionObj(serverSession);
                    displayMainMenu(socketChannel, serverSession);
                    return;
                }
                if (Files.exists(serverSession.fileToSend) && !Files.isRegularFile(serverSession.fileToSend)) {
                    System.err.println("The path specified is not a file");
                    resetServerSessionObj(serverSession);
                    displayMainMenu(socketChannel, serverSession);
                    return;
                } else if (Files.exists(serverSession.fileToSend) && Files.isRegularFile(serverSession.fileToSend)) {
                    serverSession.commandSendBuffer.clear().putInt(FILE_UPLOAD_REQUEST).flip();
                    try {
                        serverSession.encCommandSendBuffer = ByteBuffer
                                .wrap(serverSession.rsaEncrypt(serverSession.commandSendBuffer.array()));
                    } catch (Exception e) {
                        System.out.println("An error occured while encrypting the command.");
                        cleanUpServerSessionObj(serverSession);
                        return;
                    }
                    while (serverSession.encCommandSendBuffer.position() < serverSession.encCommandSendBuffer
                            .capacity()) {
                        try {
                            bytesWritten = socketChannel.write(serverSession.encCommandSendBuffer);
                            if (bytesWritten < 0) {
                                System.err.println("Server closed the connection");
                                cleanUpServerSessionObj(serverSession);
                                return;
                            }
                        } catch (Exception e) {
                            System.err.println("An error occured while writing command to server.");
                            exitApplication(true);
                        }
                    }
                    clientSendFile(socketChannel, serverSession);
                }

            }
            case "DOWNLOAD" -> {
                serverSession.commandSendBuffer.clear().putInt(FILE_SEND_REQUEST).flip();
                try {
                    serverSession.encCommandSendBuffer = ByteBuffer
                            .wrap(serverSession.rsaEncrypt(serverSession.commandSendBuffer.array()));
                } catch (Exception e) {
                    System.out.println("An error occured while encrypting the command.");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
                while (serverSession.encCommandSendBuffer.position() < serverSession.encCommandSendBuffer.capacity()) {
                    try {
                        bytesWritten = socketChannel.write(serverSession.encCommandSendBuffer);
                        if (bytesWritten < 0) {
                            System.err.println("Server closed the connection");
                            cleanUpServerSessionObj(serverSession);
                            return;
                        }
                    } catch (Exception e) {
                        System.err.println("An error occured while writing command to server.");
                        exitApplication(true);
                    }
                }
                try {
                    serverSession.encFileNameBuffer = ByteBuffer
                            .wrap(serverSession.encrypt(argument.getBytes(StandardCharsets.UTF_8)));
                } catch (Exception e) {
                    System.out.println("An error occured while encrypting the file name.");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
                serverSession.fileNameLengthBuffer.putInt(serverSession.encFileNameBuffer.capacity());
                try {
                    serverSession.encFileNameLengthBuffer = ByteBuffer
                            .wrap(serverSession.rsaEncrypt(serverSession.fileNameLengthBuffer.array()));
                } catch (Exception e) {
                    System.out.println("An error occured while encrypting the file name length.");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
                ByteBuffer[] fileSendRequest = { serverSession.encFileNameLengthBuffer,
                        serverSession.encFileNameBuffer };
                while (serverSession.encFileNameBuffer.position() < serverSession.encFileNameBuffer.capacity()) {
                    try {
                        bytesWritten = socketChannel.write(fileSendRequest);
                        if (bytesWritten < 0) {
                            System.err.println("Server closed the connection");
                            cleanUpServerSessionObj(serverSession);
                            return;
                        }
                    } catch (Exception e) {
                        System.err.println("An error occured while writing file name and name length to server.");
                        exitApplication(true);
                    }
                }
                clientReceiveFile(socketChannel, serverSession);

            }
            case "EXIT" -> {
                sendExitMessageToServer();
                exitApplication(true);

            }
            default -> {
                System.out.println("Invalid command.");
                resetServerSessionObj(serverSession);
                displayMainMenu(socketChannel, serverSession);
                return;
            }
        }

    }

    private static void readHandShake(SocketChannel socketChannel, ServerSession serverSession) throws IOException {
        // read the first 4 unencrypted bytes to get the server's ecdh public key length
        // then read the server's ecdh public key
        int bytesRead;
        if (serverSession.secretKey == null) {
            while (serverSession.serverECPublicKeyLengthBuffer.position() < serverSession.serverECPublicKeyLengthBuffer
                    .capacity()) {
                bytesRead = socketChannel.read(serverSession.serverECPublicKeyLengthBuffer);
                if (bytesRead < 0) {
                    System.err.println("Server closed the connection");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
            }

            if (serverSession.serverECPublicKeyLength == 0) {
                serverSession.serverECPublicKeyLengthBuffer.flip();
                serverSession.serverECPublicKeyLength = serverSession.serverECPublicKeyLengthBuffer.getInt();
                serverSession.serverECPublicKeyBuffer = ByteBuffer.allocate(serverSession.serverECPublicKeyLength);
            }

            while (serverSession.serverECPublicKeyBuffer.position() < serverSession.serverECPublicKeyBuffer
                    .capacity()) {
                bytesRead = socketChannel.read(serverSession.serverECPublicKeyBuffer);
                if (bytesRead < 0) {
                    System.err.println("Server closed the connection");
                    // secure wipe of serverSession.serverECPublicKeyLengthBuffer,
                    // serverSession.serverECPublicKeyBuffer, serverECPublicKeyDecodedBytes
                    Arrays.fill(serverSession.serverECPublicKeyLengthBuffer.array(), (byte) 0);
                    Arrays.fill(serverSession.serverECPublicKeyBuffer.array(), (byte) 0);

                    cleanUpServerSessionObj(serverSession);
                    return;
                }
            }

            byte[] serverECPublicKeyDecodedBytes = Base64.getDecoder()
                    .decode(serverSession.serverECPublicKeyBuffer.array());
            try {
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(serverECPublicKeyDecodedBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("EC");
                serverECPublicKey = (ECPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
            } catch (Exception e) {
                System.out.println("Failed to generate the server ecdh public key");
                // secure wipe of serverSession.serverECPublicKeyLengthBuffer,
                // serverSession.serverECPublicKeyBuffer, serverECPublicKeyDecodedBytes
                Arrays.fill(serverSession.serverECPublicKeyLengthBuffer.array(), (byte) 0);
                Arrays.fill(serverSession.serverECPublicKeyBuffer.array(), (byte) 0);
                Arrays.fill(serverECPublicKeyDecodedBytes, (byte) 0);

                cleanUpServerSessionObj(serverSession);
                return;
            }

            try {
                serverSession.secretKeySetup();
            } catch (Exception e) {
                System.err.println("Failed to generate the secret key");
                cleanUpServerSessionObj(serverSession);
                return;
            }

            // secure wipe of serverSession.serverECPublicKeyLengthBuffer,
            // serverSession.serverECPublicKeyBuffer, serverECPublicKeyDecodedBytes
            Arrays.fill(serverSession.serverECPublicKeyLengthBuffer.array(), (byte) 0);
            Arrays.fill(serverSession.serverECPublicKeyBuffer.array(), (byte) 0);
            Arrays.fill(serverECPublicKeyDecodedBytes, (byte) 0);

            return; // Returned because this is called from writeHandshake()
        }

        // read the next 256 bytes to get the nonce and server iv
        serverSession.encHandShakeReceiveBuffer = ByteBuffer.allocate(256);
        while (serverSession.encHandShakeReceiveBuffer.position() < serverSession.encHandShakeReceiveBuffer
                .capacity()) {
            bytesRead = socketChannel.read(serverSession.encHandShakeReceiveBuffer);
            if (bytesRead < 0) {
                System.err.println("Server closed the connection");
                cleanUpServerSessionObj(serverSession);
                return;
            }
        }
        serverSession.encHandShakeReceiveBuffer.flip();
        try {
            serverSession.handShakeReceiveBuffer = ByteBuffer
                    .wrap(serverSession.rsaDecrypt(serverSession.encHandShakeReceiveBuffer.array()));
        } catch (Exception e) {
            System.out.println("Failed to decrypt the hand shake");
            cleanUpServerSessionObj(serverSession);
            return;
        }
        byte[] receivedNonce = new byte[serverSession.NONCE_SIZE];
        serverSession.handShakeReceiveBuffer.get(receivedNonce);
        if (!Arrays.equals(serverSession.nonceArray, receivedNonce)) {
            System.out.println("Connected server is not a valid secure file sharing server");
            cleanUpServerSessionObj(serverSession);
            return;
        }
        serverSession.handShakeReceiveBuffer.get(serverSession.serverIV);

        System.out.println("Handshake completed successfully...");

        resetServerSessionObj(serverSession);

    }

    private static void writeHandShake(SocketChannel socketChannel, ServerSession serverSession) throws IOException {
        System.out.println("Starting handshake...");
        int bytesWritten;
        /*
         * this buffer contains
         * the handshakestringlength at 16 -> 23,
         * rsa public key length at 24 -> 27,
         * the handshakestring at 28 -> 28 + handshakestringlength,
         * the client's rsa public key at the remaining bytes
         * 
         * it is encrypted using the shared secret key
         * the server can only decrypts this if it was able to decrypt the first 256
         * bytes successfully and got the client ecdh public key to generate the shared
         * secret.
         */
        int passwordHandShakeLength = passwordHandShakeBytes.length;
        byte[] rsaPublicKeyEncodedBytes = Base64.getEncoder().encode(clientRSAPublicKey.getEncoded());
        int rsaPublicKeyStringLength = rsaPublicKeyEncodedBytes.length;
        int capacityB = 4 + 4 + passwordHandShakeLength + rsaPublicKeyStringLength;
        ByteBuffer bufferB = ByteBuffer.allocate(capacityB);
        bufferB.putInt(passwordHandShakeLength);
        bufferB.putInt(rsaPublicKeyStringLength);
        bufferB.put(passwordHandShakeBytes);
        bufferB.put(rsaPublicKeyEncodedBytes);

        /*
         * These buffer contains the following:
         * bytes 0-3: length of the remaining bytes after the first 256
         * bytes 4-19: nonce
         * remaining bytes: the client iv and the client ecdh public key
         * all of this is rsa encrypted
         * and packed into 256 bytes
         */
        serverSession.generateClientBaseIV();
        serverSession.generateNonce();
        byte[] ecPublicKeyEncodedBytes = Base64.getEncoder().encode(clientECPublicKey.getEncoded());
        int ecPublicKeyStringLength = ecPublicKeyEncodedBytes.length;
        int capacityA = 4 + serverSession.IV_SIZE + serverSession.NONCE_SIZE + ecPublicKeyStringLength;
        ByteBuffer bufferA = ByteBuffer.allocate(capacityA);
        bufferA.putInt(bufferB.capacity() + 16); // aes-gcm encryption adds extra 16-byte tag
        bufferA.put(serverSession.nonceArray);
        bufferA.put(serverSession.clientIV);
        bufferA.put(ecPublicKeyEncodedBytes);

        bufferA.flip();
        bufferB.flip();

        try {
            // encrypt bufferA and bufferB
            serverSession.encHandShakeReceiveLengthBuffer = ByteBuffer.wrap(serverSession.rsaEncrypt(bufferA.array()));

            // send encrypted bufferA
            while (serverSession.encHandShakeReceiveLengthBuffer.hasRemaining()) {
                bytesWritten = socketChannel.write(serverSession.encHandShakeReceiveLengthBuffer);
                if (bytesWritten < 0) {
                    System.err.println("Server closed the connection");
                    Arrays.fill(passwordChars, ' ');
                    Arrays.fill(passwordHandShakeChars, ' ');
                    Arrays.fill(passwordHandShakeBytes, (byte) 0);
                    Arrays.fill(bufferB.array(), (byte) 0);
                    Arrays.fill(bufferA.array(), (byte) 0);
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
            }
            if (serverSession.secretKey == null) {
                readHandShake(socketChannel, serverSession);
            }

            serverSession.encHandShakeSendBuffer = ByteBuffer.wrap(serverSession.encrypt(bufferB.array()));

        } catch (Exception e) {
            System.err.println("Failed to encrypt handshake: " + e.getMessage());
            Arrays.fill(passwordChars, ' ');
            Arrays.fill(passwordHandShakeChars, ' ');
            Arrays.fill(passwordHandShakeBytes, (byte) 0);
            Arrays.fill(bufferB.array(), (byte) 0);
            Arrays.fill(bufferA.array(), (byte) 0);
            cleanUpServerSessionObj(serverSession);
            return;
        }

        // send encrypted bufferB
        while (serverSession.encHandShakeSendBuffer.hasRemaining()) {
            bytesWritten = socketChannel.write(serverSession.encHandShakeSendBuffer);
            if (bytesWritten < 0) {
                System.err.println("Server closed the connection");
                // secure wipe of passwordchars, passwordHandShakeChars,
                // passwordHandShakeBytes, bufferA array and bufferB array
                Arrays.fill(passwordChars, ' ');
                Arrays.fill(passwordHandShakeChars, ' ');
                Arrays.fill(passwordHandShakeBytes, (byte) 0);
                Arrays.fill(bufferB.array(), (byte) 0);
                Arrays.fill(bufferA.array(), (byte) 0);
                cleanUpServerSessionObj(serverSession);
                return;
            }
        }

        // secure wipe of passwordchars, passwordHandShakeChars,
        // passwordHandShakeBytes, bufferA array and bufferB array
        Arrays.fill(passwordChars, ' ');
        Arrays.fill(passwordHandShakeChars, ' ');
        Arrays.fill(passwordHandShakeBytes, (byte) 0);
        Arrays.fill(bufferB.array(), (byte) 0);
        Arrays.fill(bufferA.array(), (byte) 0);

    }

    private static void clientReceiveFileList(SocketChannel socketChannel, ServerSession serverSession)
            throws IOException {
        int bytesRead;
        // read the first 256 bytes to get
        // 1. The command
        // 2. The file list length
        serverSession.encFileListInfoHeaderBuffer.clear();
        while (serverSession.encFileListInfoHeaderBuffer.position() < serverSession.encFileListInfoHeaderBuffer
                .capacity()) {
            bytesRead = socketChannel.read(serverSession.encFileListInfoHeaderBuffer);
            if (bytesRead < 0) {
                System.err.println("Server closed the connection");
                cleanUpServerSessionObj(serverSession);
                return;
            }
        }

        serverSession.encFileListInfoHeaderBuffer.flip();
        try {
            serverSession.fileListInfoHeaderBuffer = ByteBuffer
                    .wrap(serverSession.rsaDecrypt(serverSession.encFileListInfoHeaderBuffer.array()));
        } catch (Exception e) {
            System.err.println("An error occured while decrypting file list info details");
            cleanUpServerSessionObj(serverSession);
            return;
        }
        int commandReceived = serverSession.fileListInfoHeaderBuffer.getInt();
        if (commandReceived != FILE_LIST) {
            System.out.println("Invalid command received from server; expected a file list command");
            cleanUpServerSessionObj(serverSession);
            return;
        }
        long lengthOfEncFileList = serverSession.fileListInfoHeaderBuffer.getLong();
        // create a buffer to receive the encrypted file list
        serverSession.encFileListBuffer = ByteBuffer.allocate((int) lengthOfEncFileList);
        while (serverSession.encFileListBuffer.position() < serverSession.encFileListBuffer.capacity()) {
            socketChannel.read(serverSession.encFileListBuffer);
        }
        serverSession.encFileListBuffer.flip();
        try {
            serverSession.decFileListBuffer = ByteBuffer
                    .wrap(serverSession.decrypt(serverSession.encFileListBuffer.array()));
        } catch (Exception e) {
            System.err.println("An error occured while decrypting file list");
            cleanUpServerSessionObj(serverSession);
            return;
        }
        String fileList = new String(serverSession.decFileListBuffer.array(), StandardCharsets.UTF_8);
        System.out.println("\n" + fileList);
        resetServerSessionObj(serverSession);
        displayMainMenu(socketChannel, serverSession);
        return;

    }

    private static void clientPrintInformation(SocketChannel socketChannel, ServerSession serverSession)
            throws IOException {
        // this method is called from clientReceiveFileMethod when the client sends a
        // request to download a file that does not exist on the server
        // read 4 bytes read to determine the length of the encrypted information
        // then the encrypted information is read

        int informationLength = serverSession.informationDetailsBuffer.getInt();
        serverSession.encInformationBuffer = ByteBuffer.allocate(informationLength);
        while (serverSession.encInformationBuffer.position() < serverSession.encInformationBuffer.capacity()) {
            socketChannel.read(serverSession.encInformationBuffer);
        }
        serverSession.encInformationBuffer.flip();
        try {
            serverSession.decInformationBuffer = ByteBuffer
                    .wrap(serverSession.decrypt(serverSession.encInformationBuffer.array()));
        } catch (Exception e) {
            System.err.println("An error occured while decrypting information");
            return;
        }
        String information = new String(serverSession.decInformationBuffer.array(), StandardCharsets.UTF_8);
        System.out.println(information);
    }

    private static void clientSendFile(SocketChannel socketChannel, ServerSession serverSession) throws IOException {
        long bytesWritten;
        serverSession.fileName = serverSession.fileToSend.getFileName().toString();
        serverSession.fileSize = Files.size(serverSession.fileToSend);
        try {
            serverSession.encFileNameBuffer = ByteBuffer
                    .wrap(serverSession.encrypt(serverSession.fileName.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.err.println("An error occured while encrypting file name");
            cleanUpServerSessionObj(serverSession);
            return;
        }
        serverSession.unEncFileDetails256 = ByteBuffer.allocate(8 + 4); // 8 bytes for file size and 4 bytes for file
                                                                        // name length
        serverSession.unEncFileDetails256.putLong(serverSession.fileSize)
                .putInt(serverSession.encFileNameBuffer.capacity()).flip();
        try {
            serverSession.encFileDetails256 = ByteBuffer
                    .wrap(serverSession.rsaEncrypt(serverSession.unEncFileDetails256.array()));
        } catch (Exception e) {
            System.err.println("An error occured while encrypting file details");
            cleanUpServerSessionObj(serverSession);
            return;
        }
        // send the first 256 bytes which is encrypted and contain the file size and
        // file name length
        while (serverSession.encFileDetails256.position() < serverSession.encFileDetails256.capacity()) {
            bytesWritten = socketChannel.write(serverSession.encFileDetails256);
            if (bytesWritten < 0) {
                System.err.println("Server closed the connection");
                cleanUpServerSessionObj(serverSession);
                return;
            }
        }
        // send the file name
        while (serverSession.encFileNameBuffer.position() < serverSession.encFileNameBuffer.capacity()) {
            bytesWritten = socketChannel.write(serverSession.encFileNameBuffer);
            if (bytesWritten < 0) {
                System.err.println("Server closed the connection");
                cleanUpServerSessionObj(serverSession);
                return;
            }
        }
        // send the file in chunks
        if (serverSession.fileChannel == null || !serverSession.fileChannel.isOpen()) {
            try {
                serverSession.fileChannel = FileChannel.open(serverSession.fileToSend, StandardOpenOption.READ);
                serverSession.fileSize = serverSession.fileChannel.size();
            } catch (Exception e) {
                System.err
                        .println("Could not send file chunk; an error occured while opening fileChannel on the file : "
                                + serverSession.fileName);
                cleanUpServerSessionObj(serverSession);
                return;
            }
        }
        if (serverSession.fileChannel.isOpen()) {
            long bytesReadFromFile = 0;
            while (serverSession.fileChannelPosition < serverSession.fileSize) {
                serverSession.unencryptedFileChunkBuffer.clear();
                bytesReadFromFile = serverSession.fileChannel.read(serverSession.unencryptedFileChunkBuffer,
                        serverSession.fileChannelPosition);
                if (bytesReadFromFile < 0) {
                    System.err.println("An error occured while reading from fileChannel");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
                serverSession.fileChannelPosition += bytesReadFromFile;
                serverSession.unencryptedFileChunkBuffer.flip();

                byte[] validBytes = new byte[serverSession.unencryptedFileChunkBuffer.remaining()];
                serverSession.unencryptedFileChunkBuffer.get(validBytes);
                byte[] encFileChunkBytes;
                try {
                    encFileChunkBytes = serverSession
                            .encrypt(validBytes);
                } catch (Exception e) {
                    System.err.println("An error occured while encrypting the file chunk");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
                serverSession.directFileChunkBuffer.clear().put(encFileChunkBytes).flip();
                serverSession.chunkLengthBuffer.clear().putInt(serverSession.directFileChunkBuffer.remaining()).flip();
                byte[] encLengthBytes;
                try {
                    encLengthBytes = serverSession.rsaEncrypt(serverSession.chunkLengthBuffer.array());
                } catch (Exception e) {
                    System.err.println(
                            "An error occured while encrypting the length of the file chunk");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
                serverSession.encChunkLengthBuffer.clear().put(encLengthBytes).flip();

                /*
                 * Encrypted chunk length at the first 256 bytes
                 * Encrypted chunk at the remaining bytes
                 */
                serverSession.encChunkLengthAndDataArr = new ByteBuffer[] {
                        serverSession.encChunkLengthBuffer,
                        serverSession.directFileChunkBuffer
                };
                while (serverSession.directFileChunkBuffer.hasRemaining()) {
                    bytesWritten = socketChannel.write(serverSession.encChunkLengthAndDataArr);
                    if (bytesWritten < 0) {
                        System.err.println("Server closed the connection");
                        cleanUpServerSessionObj(serverSession);
                        return;
                    }
                }
                serverSession.printProgress(serverSession.fileChannelPosition, serverSession.fileSize);

            }
            System.out.println("\nFile sent to server: " + serverSession.fileName);
            resetServerSessionObj(serverSession);
            displayMainMenu(socketChannel, serverSession);
            return;

        }
    }

    private static void clientReceiveFile(SocketChannel socketChannel, ServerSession serverSession) throws IOException {
        // read the first 256 encrypted bytes
        // decrypt and read the first 4 bytes to get the command
        // possible commands: FILE_DOWNLOAD, INFORMATION
        int bytesRead;
        while (serverSession.encFileDetails256.position() < serverSession.encFileDetails256.capacity()) {
            bytesRead = socketChannel.read(serverSession.encFileDetails256);
            if (bytesRead < 0) {
                System.err.println("Server closed the connection");
                cleanUpServerSessionObj(serverSession);
                return;
            }
        }
        serverSession.encFileDetails256.flip();
        try {
            serverSession.unEncFileDetails256 = ByteBuffer
                    .wrap(serverSession.rsaDecrypt(serverSession.encFileDetails256.array()));
        } catch (Exception e) {
            System.err.println("An error occured while decrypting file details");
            cleanUpServerSessionObj(serverSession);
            return;
        }
        int command = serverSession.unEncFileDetails256.getInt();
        if (command == FILE_DOWNLOAD) {
            // next 8 bytes is the file size
            // next 4 bytes is the length of the encrypted file name
            serverSession.fileSize = serverSession.unEncFileDetails256.getLong();
            serverSession.fileNameLength = serverSession.unEncFileDetails256.getInt();
            // read the encrypted file name, decrypt it and create the empty file
            serverSession.encFileNameBuffer = ByteBuffer.allocate(serverSession.fileNameLength);
            while (serverSession.encFileNameBuffer.position() < serverSession.encFileNameBuffer.capacity()) {
                bytesRead = socketChannel.read(serverSession.encFileNameBuffer);
                if (bytesRead < 0) {
                    System.err.println("Server closed the connection");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }
            }
            try {
                serverSession.fileNameBuffer = ByteBuffer
                        .wrap(serverSession.decrypt(serverSession.encFileNameBuffer.array()));
            } catch (Exception e) {
                System.out.println("An error occured while decrypting file name");
                cleanUpServerSessionObj(serverSession);
                return;
            }
            serverSession.fileName = new String(serverSession.fileNameBuffer.array(), StandardCharsets.UTF_8);
            if (!serverSession.fileName.isBlank() && serverSession.fileSize > 0) {
                serverSession.filePath = clientDownloadPath.resolve(serverSession.fileName);
                int lastDotIndex = serverSession.fileName.lastIndexOf(".");
                if (lastDotIndex == -1)
                    return;
                serverSession.fileExtension = serverSession.fileName.substring(lastDotIndex);
                serverSession.fileNameWithoutExtension = serverSession.fileName.substring(0, lastDotIndex);

                int counter = 0;
                while (true) {
                    if (Files.exists(serverSession.filePath)) {
                        counter++;

                        String regex = "\\(\\d+\\)$";
                        String cleanName = serverSession.fileNameWithoutExtension.replaceAll(regex, "");
                        serverSession.fileNameWithoutExtension = cleanName;

                        serverSession.filePath = clientDownloadPath.resolve(
                                serverSession.fileNameWithoutExtension + "(" + counter + ")"
                                        + serverSession.fileExtension);

                        serverSession.fileName = serverSession.filePath.getFileName().toString();

                        int lastDotIndexNew = serverSession.fileName.lastIndexOf(".");
                        if (lastDotIndexNew != -1) {
                            serverSession.fileExtension = serverSession.fileName.substring(lastDotIndexNew);
                            serverSession.fileNameWithoutExtension = serverSession.fileName.substring(0,
                                    lastDotIndexNew);
                        }
                    } else {
                        try {
                            Files.createFile(serverSession.filePath);
                        } catch (Exception e) {
                            System.err.println("Failed to create file: " + serverSession.filePath.toAbsolutePath());
                            cleanUpServerSessionObj(serverSession);
                            return;
                        }
                        break;
                    }
                }
                // open the file channel
                try {
                    serverSession.fileChannel = FileChannel.open(serverSession.filePath, StandardOpenOption.WRITE,
                            StandardOpenOption.APPEND);
                } catch (IOException e) {
                    System.err.println("Failed to open file channel");
                    cleanUpServerSessionObj(serverSession);
                    return;
                }

                // get the length of the chunk to be received
                // receive and decrypt the chunk
                // append the decrypted chunk to file
                // repeat until the file size is reached
                while (serverSession.fileChannel.size() < serverSession.fileSize) {
                    serverSession.encChunkLengthBuffer.clear();
                    while (serverSession.encChunkLengthBuffer.position() < serverSession.encChunkLengthBuffer
                            .capacity()) {
                        bytesRead = socketChannel.read(serverSession.encChunkLengthBuffer);
                        if (bytesRead < 0) {
                            System.err.println("Server closed the connection");
                            cleanUpServerSessionObj(serverSession);
                            return;
                        }
                    }
                    try {
                        byte[] decChunkLengthBytes = serverSession
                                .rsaDecrypt(serverSession.encChunkLengthBuffer.array());
                        serverSession.chunkLengthBuffer.clear().put(decChunkLengthBytes).flip();
                        serverSession.lengthOfEncryptedChunk = serverSession.chunkLengthBuffer.getInt();
                        serverSession.encChunkLengthBuffer.clear();
                    } catch (Exception e) {
                        System.err.println("An error occured while decrypting the chunk length from server");
                        cleanUpServerSessionObj(serverSession);
                        return;
                    }

                    serverSession.encryptedFileChunkBuffer.clear();
                    while (serverSession.encryptedFileChunkBuffer.position() < serverSession.lengthOfEncryptedChunk) {
                        bytesRead = socketChannel.read(serverSession.encryptedFileChunkBuffer);
                        if (bytesRead < 0) {
                            System.err.println("Server closed the connection");
                            cleanUpServerSessionObj(serverSession);
                            return;
                        }
                    }
                    serverSession.encryptedFileChunkBuffer.flip();
                    try {
                        byte[] validEncryptedBytes = new byte[serverSession.encryptedFileChunkBuffer.remaining()];
                        serverSession.encryptedFileChunkBuffer.get(validEncryptedBytes);
                        byte[] decFileChunkBytes = serverSession
                                .decrypt(validEncryptedBytes);
                        serverSession.directFileChunkBuffer.clear().put(decFileChunkBytes).flip();
                    } catch (Exception e) {
                        System.err.println("An error occured while decrypting the file chunk from server");
                        cleanUpServerSessionObj(serverSession);
                        return;
                    }
                    serverSession.fileChannel.write(serverSession.directFileChunkBuffer);
                    serverSession.fileChannel.force(true);
                    serverSession.printProgress(serverSession.fileChannel.size(), serverSession.fileSize);
                }
                System.out.println("\nFile recieved from server: " + serverSession.fileName);
                serverSession.fileChannel.close();
                resetServerSessionObj(serverSession);
                displayMainMenu(socketChannel, serverSession);
                return;

            }

        } else if (command == INFORMATION) {
            serverSession.informationDetailsBuffer = ByteBuffer.allocate(serverSession.unEncFileDetails256.remaining());
            serverSession.informationDetailsBuffer.put(serverSession.unEncFileDetails256).flip();
            clientPrintInformation(socketChannel, serverSession);
            resetServerSessionObj(serverSession);
            displayMainMenu(socketChannel, serverSession);
            return;

        } else {
            System.err.println("Invalid Command Received; expected FILE_DOWNLOAD or INFORMATION");
            exitApplication(true);
        }
    }

    private static void exitApplication(boolean userInitiated) {
        if (serverSession != null) {
            cleanUpServerSessionObj(serverSession);
        }
        if (socketChannel != null && socketChannel.isOpen()) {
            try {
                socketChannel.close();
            } catch (IOException e) {
                System.err.println("An error occured while closing the socket channel.");
            }
        }
        try {
            Files.deleteIfExists(clientTempPath);
        } catch (IOException e) {
            System.err.println("An error occured while deleting the temporary folder.");
        }
        if (userInitiated) {
            System.exit(0); // called if the exit was requested by the user and not the shutdown hook
        }
    }

    private static void sendExitMessageToServer() {
        int bytesWritten;
        if (serverSession != null && serverSession.commandSendBuffer != null) {
            serverSession.commandSendBuffer.clear().putInt(EXIT).flip();
            try {
                serverSession.encCommandSendBuffer = ByteBuffer
                        .wrap(serverSession.rsaEncrypt(serverSession.commandSendBuffer.array()));
            } catch (Exception e) {
                System.out.println("An error occured while encrypting the command.");
                cleanUpServerSessionObj(serverSession);
                return;
            }
            while (serverSession.encCommandSendBuffer.position() < serverSession.encCommandSendBuffer.capacity()) {
                if (socketChannel != null && socketChannel.isOpen()) {
                    try {
                        bytesWritten = socketChannel.write(serverSession.encCommandSendBuffer);
                        if (bytesWritten < 0) {
                            System.err.println("Server closed the connection");
                            cleanUpServerSessionObj(serverSession);
                            return;
                        }
                    } catch (Exception e) {
                        System.err.println("An error occured while writing command to server.");
                        exitApplication(true);
                    }
                }
            }
        }
    }

    private static void cleanUpServerSessionObj(ServerSession serverSession) {
        serverSession.progressState = null;
        serverSession.chunkStatus = null;
        serverSession.encHandShakeSendBuffer = null;
        serverSession.handShakeReceiveBuffer = null;
        serverSession.encHandShakeReceiveBuffer = null;
        serverSession.informationDetailsBuffer = null;
        serverSession.encInformationDetailsBuffer = null;
        serverSession.decInformationDetailsBuffer = null;
        serverSession.informationBuffer = null;
        serverSession.decInformationStringBuffer = null;
        serverSession.encInformationBuffer = null;
        serverSession.decInformationBuffer = null;
        serverSession.fileNameBuffer = null;
        serverSession.encFileNameBuffer = null;
        serverSession.decFileNameBuffer = null;
        serverSession.serverECPublicKeyBuffer = null;
        serverSession.serverECPublicKeyLengthBuffer = null;
        serverSession.commandReceiveBuffer = null;
        serverSession.commandSendBuffer = null;
        serverSession.encCommandReceiveBuffer = null;
        serverSession.encCommandSendBuffer = null;
        serverSession.fileNameLengthBuffer = null;
        serverSession.encHandShakeSendLengthBuffer = null;
        serverSession.handShakeReceiveLengthBuffer = null;
        serverSession.encHandShakeReceiveLengthBuffer = null;
        serverSession.encFileListLengthBuffer = null;
        serverSession.encFileNameLengthBuffer = null;
        serverSession.decFileNameLengthBuffer = null;
        serverSession.informationLengthBuffer = null;
        serverSession.encInformationLengthBuffer = null;
        serverSession.decInformationLengthBuffer = null;
        serverSession.fileSizeBuffer = null;
        serverSession.encFileSizeBuffer = null;
        serverSession.decFileSizeBuffer = null;
        serverSession.chunkLengthBuffer = null;
        serverSession.encChunkLengthBuffer = null;
        serverSession.encFileListInfoHeaderBuffer = null;
        serverSession.fileListInfoHeaderBuffer = null;
        serverSession.unEncFileDetails256 = null;
        serverSession.encFileDetails256 = null;
        serverSession.encFileListBuffer = null;
        serverSession.decFileListBuffer = null;
        serverSession.informationBufferArr = null;
        serverSession.fileDetailsBufferArr = null;
        serverSession.encChunkLengthAndDataArr = null;
        serverSession.fileChannel = null;
        serverSession.fileListTempFile = null;
        serverSession.command = NO_COMMAND;
        serverSession.encryptedFileListStringLength = 0;
        serverSession.fileNameLength = 0;
        serverSession.encFileNameLength = 0;
        serverSession.decFileNameLength = 0;
        serverSession.lengthOfEncryptedChunk = 0;
        serverSession.fileSize = 0;
        serverSession.c2cTransferCurrentPosition = 0;
        serverSession.fileChannelPosition = 0;
        serverSession.information = null;
        serverSession.fileName = null;
        serverSession.fileNameWithoutExtension = null;
        serverSession.fileExtension = null;

        serverSession.fileToSend = null;
        serverSession.filePath = null;

        // clear nonce used in handshake
        serverSession.nonceArray = null;

        // reset buffers used in chunk transfer
        serverSession.directFileChunkBuffer = null;
        serverSession.unencryptedFileChunkBuffer = null;
        serverSession.encryptedFileChunkBuffer = null;

        serverSession.nonceArray = null;
        serverSession.additionalData = null;
        serverSession.additionalDataBytes = null;

        serverSession.secretKey = null;
        serverSession.decryptCipher = null;
        serverSession.encryptCipher = null;
        serverSession.rsaDecryptCipher = null;
        serverSession.rsaEncryptCipher = null;

        serverSession.serverIV = null;
        serverSession.clientIV = null;

        if (serverSession.fileChannel != null && serverSession.fileChannel.isOpen()) {
            try {
                serverSession.fileChannel.close();
            } catch (Exception e) {
                System.err.println("Could not close file channel: " + e.getMessage());
            }
            serverSession.fileChannel = null;
        }
    }

    private static void resetServerSessionObj(ServerSession serverSession) {
        serverSession.progressState = Progress.VALID_HANDSHAKE;
        serverSession.chunkStatus = ChunkProgress.DEFAULT;
        serverSession.encHandShakeSendBuffer = null;
        serverSession.handShakeReceiveBuffer = null;
        serverSession.encHandShakeReceiveBuffer = null;
        serverSession.informationDetailsBuffer = null;
        serverSession.encInformationDetailsBuffer = null;
        serverSession.decInformationDetailsBuffer = null;
        serverSession.informationBuffer = null;
        serverSession.decInformationStringBuffer = null;
        serverSession.encInformationBuffer = null;
        serverSession.decInformationBuffer = null;
        serverSession.fileNameBuffer = null;
        serverSession.encFileNameBuffer = null;
        serverSession.decFileNameBuffer = null;
        serverSession.serverECPublicKeyBuffer = null;
        serverSession.serverECPublicKeyLengthBuffer.clear();
        serverSession.commandReceiveBuffer.clear();
        serverSession.commandSendBuffer.clear();
        serverSession.encCommandReceiveBuffer.clear();
        serverSession.encCommandSendBuffer.clear();
        serverSession.fileNameLengthBuffer.clear();
        serverSession.encHandShakeSendLengthBuffer.clear();
        serverSession.handShakeReceiveLengthBuffer.clear();
        serverSession.encHandShakeReceiveLengthBuffer.clear();
        serverSession.encFileListLengthBuffer.clear();
        serverSession.encFileNameLengthBuffer.clear();
        serverSession.decFileNameLengthBuffer.clear();
        serverSession.informationLengthBuffer.clear();
        serverSession.encInformationLengthBuffer.clear();
        serverSession.decInformationLengthBuffer.clear();
        serverSession.fileSizeBuffer.clear();
        serverSession.encFileSizeBuffer.clear();
        serverSession.decFileSizeBuffer.clear();
        serverSession.chunkLengthBuffer.clear();
        serverSession.encChunkLengthBuffer.clear();
        serverSession.encFileListInfoHeaderBuffer.clear();
        serverSession.fileListInfoHeaderBuffer = null;
        serverSession.unEncFileDetails256 = null;
        serverSession.encFileDetails256.clear();
        serverSession.encFileListBuffer = null;
        serverSession.decFileListBuffer = null;
        serverSession.informationBufferArr = null;
        serverSession.fileDetailsBufferArr = null;
        serverSession.encChunkLengthAndDataArr = null;
        serverSession.fileListTempFile = null;
        serverSession.command = NO_COMMAND;
        serverSession.encryptedFileListStringLength = 0;
        serverSession.fileNameLength = 0;
        serverSession.encFileNameLength = 0;
        serverSession.decFileNameLength = 0;
        serverSession.lengthOfEncryptedChunk = 0;
        serverSession.serverECPublicKeyLength = 0;
        serverSession.fileSize = 0;
        serverSession.c2cTransferCurrentPosition = 0;
        serverSession.fileChannelPosition = 0;
        serverSession.information = "";
        serverSession.fileName = "";
        serverSession.fileNameWithoutExtension = "";
        serverSession.fileExtension = "";

        serverSession.fileToSend = null;
        serverSession.filePath = null;

        if (serverSession.fileChannel != null && serverSession.fileChannel.isOpen()) {
            try {
                serverSession.fileChannel.close();
            } catch (Exception e) {
                System.err.println("Could not close file channel: " + e.getMessage());
            }
        }

        // clear nonce used in handshake
        serverSession.nonceArray = null;

        // reset buffers used in chunk transfer
        serverSession.directFileChunkBuffer.clear();
        serverSession.unencryptedFileChunkBuffer.clear();
    }

    private static class ServerSession {
        Progress progressState = null;
        ChunkProgress chunkStatus = ChunkProgress.DEFAULT;
        ByteBuffer encHandShakeSendBuffer = null;
        ByteBuffer handShakeReceiveBuffer = null;
        ByteBuffer encHandShakeReceiveBuffer = null;
        ByteBuffer informationDetailsBuffer = null;
        ByteBuffer encInformationDetailsBuffer = null;
        ByteBuffer decInformationDetailsBuffer = null;
        ByteBuffer informationBuffer = null;
        ByteBuffer decInformationStringBuffer = null;
        ByteBuffer encInformationBuffer = null;
        ByteBuffer decInformationBuffer = null;
        ByteBuffer fileNameBuffer = null;
        ByteBuffer encFileNameBuffer = null;
        ByteBuffer decFileNameBuffer = null;
        ByteBuffer serverECPublicKeyBuffer = null;
        ByteBuffer serverECPublicKeyLengthBuffer = ByteBuffer.allocate(4);
        ByteBuffer commandReceiveBuffer = ByteBuffer.allocate(4);
        ByteBuffer encCommandReceiveBuffer = ByteBuffer.allocate(256);
        ByteBuffer commandSendBuffer = ByteBuffer.allocate(4);
        ByteBuffer encCommandSendBuffer = ByteBuffer.allocate(256);
        ByteBuffer fileNameLengthBuffer = ByteBuffer.allocate(4);
        ByteBuffer encHandShakeSendLengthBuffer = ByteBuffer.allocate(256);
        ByteBuffer handShakeReceiveLengthBuffer = ByteBuffer.allocate(4);
        ByteBuffer encHandShakeReceiveLengthBuffer = ByteBuffer.allocate(256);
        ByteBuffer informationLengthBuffer = ByteBuffer.allocate(4);
        ByteBuffer encInformationLengthBuffer = ByteBuffer.allocate(256);
        ByteBuffer decInformationLengthBuffer = ByteBuffer.allocate(4);
        ByteBuffer encFileListLengthBuffer = ByteBuffer.allocate(256);
        ByteBuffer encFileNameLengthBuffer = ByteBuffer.allocate(256);
        ByteBuffer decFileNameLengthBuffer = ByteBuffer.allocate(4);
        ByteBuffer fileSizeBuffer = ByteBuffer.allocate(8);
        ByteBuffer encFileSizeBuffer = ByteBuffer.allocate(256);
        ByteBuffer decFileSizeBuffer = ByteBuffer.allocate(256);
        ByteBuffer chunkLengthBuffer = ByteBuffer.allocate(4);
        ByteBuffer encChunkLengthBuffer = ByteBuffer.allocate(256);
        ByteBuffer encFileListInfoHeaderBuffer = ByteBuffer.allocate(256);
        ByteBuffer fileListInfoHeaderBuffer = null;
        ByteBuffer unEncFileDetails256 = null;
        ByteBuffer encFileDetails256 = ByteBuffer.allocate(256);
        ByteBuffer encFileListBuffer = null;
        ByteBuffer decFileListBuffer = null;
        ByteBuffer[] informationBufferArr = null;
        ByteBuffer[] fileDetailsBufferArr = null;
        ByteBuffer[] encChunkLengthAndDataArr = null;
        ByteBuffer[] encHandShakeBuffersArr = null;
        FileChannel fileChannel = null;
        Path fileListTempFile = null;
        int command = NO_COMMAND;
        long encryptedFileListStringLength = 0;
        int fileNameLength = 0;
        int encFileNameLength = 0;
        int decFileNameLength = 0;
        int lengthOfEncryptedChunk = 0;
        int serverECPublicKeyLength = 0;
        long fileSize = 0;
        long c2cTransferCurrentPosition = 0;
        long fileChannelPosition = 0;
        String information = "";
        String fileName = "";
        String fileNameWithoutExtension = "";
        String fileExtension = "";

        Path fileToSend;
        Path filePath;

        final int ENCRYPTED_CHUNK_SIZE = 64 * 1024;
        final int UNENCRYPTED_CHUNK_SIZE = ENCRYPTED_CHUNK_SIZE - 16;

        ByteBuffer directFileChunkBuffer = ByteBuffer.allocateDirect(ENCRYPTED_CHUNK_SIZE);
        ByteBuffer unencryptedFileChunkBuffer = ByteBuffer.allocate(UNENCRYPTED_CHUNK_SIZE);
        ByteBuffer encryptedFileChunkBuffer = ByteBuffer.allocate(ENCRYPTED_CHUNK_SIZE);

        // Encryption and Decryption
        private final int IV_SIZE = 12;
        private final int TAG_BIT_LENGTH = 128;
        private final int NONCE_SIZE = 16;
        private byte[] nonceArray = new byte[NONCE_SIZE];
        private String additionalData = "SECURE_FILE_SHARING_V1";
        private byte[] additionalDataBytes = additionalData.getBytes();
        private SecretKey secretKey;

        Cipher encryptCipher;
        Cipher decryptCipher;
        Cipher rsaEncryptCipher;
        Cipher rsaDecryptCipher;

        private ServerSession() throws Exception {
            encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
            rsaEncryptCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsaDecryptCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        }

        byte[] serverIV = new byte[IV_SIZE];
        byte[] clientIV = new byte[IV_SIZE];
        long serverIVCounter = 0;
        long clientIVCounter = 0;

        // IV modifier is used to modify IV for each message
        // IV modifier puts a long into the IV starting at the fourth byte
        ByteBuffer serverIVModifierBuffer = ByteBuffer.wrap(serverIV, 4, 8);
        ByteBuffer clientIVModifierBuffer = ByteBuffer.wrap(clientIV, 4, 8);

        SecureRandom secureRandom = new SecureRandom();

        private void generateClientBaseIV() {
            secureRandom.nextBytes(clientIV);
        }

        private void generateNonce() {
            secureRandom.nextBytes(nonceArray);
        }

        private void setupServerBaseIV(byte[] receivedServerBaseIV) {
            System.arraycopy(receivedServerBaseIV, 0, serverIV, 0, IV_SIZE);
        }

        private void secretKeySetup() throws Exception {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(clientECPrivateKey);
            ka.doPhase(serverECPublicKey, true);
            byte[] rawSecret = ka.generateSecret();

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(rawSecret);
            SecretKeySpec secretKeySpec = new SecretKeySpec(hash, "AES");
            secretKey = secretKeySpec;
        }

        private byte[] encrypt(byte[] dataToEncrypt) throws Exception {
            GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, clientIV);
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            encryptCipher.updateAAD(additionalDataBytes);
            byte[] cipherText = encryptCipher.doFinal(dataToEncrypt);

            clientIVModifierBuffer.putLong(0, clientIVCounter++);

            return cipherText;
        }

        private byte[] decrypt(byte[] encryptedData) throws Exception {
            GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, serverIV);
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            decryptCipher.updateAAD(additionalDataBytes);

            serverIVModifierBuffer.putLong(0, serverIVCounter++);

            return decryptCipher.doFinal(encryptedData);

        }

        private byte[] rsaEncrypt(byte[] dataToEncrypt) throws Exception {
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            rsaEncryptCipher.init(Cipher.ENCRYPT_MODE, serverRSAPublicKey, spec);
            return rsaEncryptCipher.doFinal(dataToEncrypt);
        }

        private byte[] rsaDecrypt(byte[] encryptedData) throws Exception {
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            rsaDecryptCipher.init(Cipher.DECRYPT_MODE, clientRSAPrivateKey, spec);
            return rsaDecryptCipher.doFinal(encryptedData);
        }

        private long totalNumberOfBars = 20;

        private void printProgress(long current, long total) {
            long percentage = (current * 100) / total;
            long currentNumberOfBars = (current * totalNumberOfBars) / total;
            StringBuilder msg = new StringBuilder().append("[");
            for (int i = 1; i <= totalNumberOfBars; i++) {
                if (i <= currentNumberOfBars) {
                    msg.append("#");
                } else
                    msg.append("_");
            }
            msg.append("]").append(" " + percentage + "% ").append(current + "/" + total + " bytes.");
            println(msg.toString());
        }

        private int lastLineLength = 0;

        private void println(String message) {
            System.out.print("\r " + message);
            int currentLineLength = "\r ".length() + message.length();
            for (int i = currentLineLength; i < lastLineLength; i++) {
                System.out.print(" ");
            }
            lastLineLength = currentLineLength;
        }
    }

}