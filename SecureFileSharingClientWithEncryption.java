import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
import java.security.spec.PKCS8EncodedKeySpec;
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
    private static final int NO_COMMAND = 0;
    private static final int FILE_SEND_REQUEST = 1;
    private static final int FILE_UPLOAD_REQUEST = 2;
    private static final int FILE_DOWNLOAD = 3;
    private static final int FILE_LIST_REQUEST = 4;
    private static final int FILE_LIST = 5;
    private static final int INFORMATION = 6;
    private static String HANDSHAKE_STRING = "SecureFileSharingHandShake";
    private static long TEMPFILENUMBER = 0;
    private static Path clientDownloadPath = Paths.get(System.getProperty("user.home"),
            "SecureFileSharingClientWithEncryption");
    private static Path clientTempPath = Paths.get(System.getProperty("java.io.tmpdir"),
            "SecureFileSharingClientWithEncryptionTemp");
    private static String serverIPAdress;
    private static Scanner userInput = new Scanner(System.in);

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
    private static final String SERVER_RSA_PUBLIC_KEY_STRING = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+TEpsZJxq1bDlcGsy4a//RRq3MMfYeE+1J6yL9LiqCf0hbdBE4y86sQjbUquoYi6VpTITiw7uzMg3wzRmkqABFtcbOtzNEeHSpqgMv88YRDlPbVutsE4JAxmm6BkA2cLqIgjM6jbZRrnR5kwaw/jWFmhOpazNRH/c6HWQ3KLFAUc/ZXBchm69gFOdtGJ939rzE9zzpLo5t+lp/kAbXbdug98Geo7Nky5A3rv3ooFAaRgwovCCKQWoKGFKndgk1TootJuLBH+DaeQ+sjDhlAByrygwuV9pPS31r1lYoWQ8Ls5RclfVIDxJLpmOxjx0x1Qn6ixnQ7P75Uy6rA9s3PiwIDAQAB";
    private static RSAPublicKey serverRSAPublicKey;
    private static ECPublicKey serverECPublicKey;

    public static void main(String[] args) {
        try {
            byte[] serverRSAPublicKeyBytes = Base64.getDecoder().decode(SERVER_RSA_PUBLIC_KEY_STRING);
            serverRSAPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(serverRSAPublicKeyBytes));
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
        String serverPassword = userInput.nextLine();
        HANDSHAKE_STRING += serverPassword;
        serverAddress = new InetSocketAddress(serverIPAdress, PORT);
        try (SocketChannel socketChannel = SocketChannel.open()) {
            socketChannel.configureBlocking(true);
            System.out.println("Connecting to server...");
            socketChannel.connect(serverAddress);
            if (socketChannel.isConnected()) {
                System.out.println("Connected to server successfully...");
                System.out.println("Authenticating server...");
                ServerSession serverSession = new ServerSession();
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

    private static void displayMainMenu(SocketChannel socketChannel, ServerSession serverSession) {
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
        System.out.print("Enter command: ");
        String userRequest = userInput.nextLine();
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
        int handShakeStringLength = HANDSHAKE_STRING.length();
        byte[] rsaPublicKeyEncodedBytes = Base64.getEncoder().encode(clientRSAPublicKey.getEncoded());
        int rsaPublicKeyStringLength = rsaPublicKeyEncodedBytes.length;
        int capacityB = 4 + 4 + handShakeStringLength + rsaPublicKeyStringLength;
        ByteBuffer bufferB = ByteBuffer.allocate(capacityB);
        bufferB.putInt(handShakeStringLength);
        bufferB.putInt(rsaPublicKeyStringLength);
        bufferB.put(HANDSHAKE_STRING.getBytes(StandardCharsets.UTF_8));
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
            // this contains bufferA in encrypted form
            serverSession.encHandShakeReceiveLengthBuffer = ByteBuffer.wrap(serverSession.rsaEncrypt(bufferA.array()));
            while (serverSession.encHandShakeReceiveLengthBuffer.hasRemaining()) {
                bytesWritten = socketChannel.write(serverSession.encHandShakeReceiveLengthBuffer);
                if (bytesWritten < 0) {
                    System.err.println("Server closed the connection");
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
            cleanUpServerSessionObj(serverSession);
            return;
        }

        System.out.println("Point F");
        while (serverSession.encHandShakeSendBuffer.hasRemaining()) {
            bytesWritten = socketChannel.write(serverSession.encHandShakeSendBuffer);
            if (bytesWritten < 0) {
                System.err.println("Server closed the connection");
                cleanUpServerSessionObj(serverSession);
                return;
            }
        }
        System.out.println("Point G");

    }

    private static void clientReceiveFileList(SocketChannel socketChannel, ServerSession serverSession)
            throws IOException {
    }

    private static void clientReceiveInformation(SocketChannel socketChannel, ServerSession serverSession)
            throws IOException {
    }

    private static void clientSendFile(SocketChannel socketChannel, ServerSession serverSession) throws IOException {
    }

    private static void clientReceiveFile(SocketChannel socketChannel, ServerSession serverSession) throws IOException {
    }

    private static void cleanUpServerSessionObj(ServerSession serverSession) {
        serverSession.progressState = null;
        serverSession.chunkStatus = null;
        serverSession.encHandShakeSendBuffer = null;
        serverSession.handShakeReceiveBuffer = null;
        serverSession.encHandShakeReceiveBuffer = null;
        serverSession.informationBuffer = null;
        serverSession.encInformationStringBuffer = null;
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
        serverSession.informationBuffer = null;
        serverSession.encInformationStringBuffer = null;
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
        ByteBuffer informationBuffer = null;
        ByteBuffer encInformationStringBuffer = null;
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

        final int ENCRYPTED_CHUNK_SIZE = 64 * 1024;
        final int UNENCRYPTED_CHUNK_SIZE = ENCRYPTED_CHUNK_SIZE - 16;

        ByteBuffer directFileChunkBuffer = ByteBuffer.allocateDirect(ENCRYPTED_CHUNK_SIZE);
        ByteBuffer unencryptedFileChunkBuffer = ByteBuffer.allocate(UNENCRYPTED_CHUNK_SIZE);
        ByteBuffer encryptedFileChunkBuffer = ByteBuffer.allocate(ENCRYPTED_CHUNK_SIZE);

        // Encryption and Decryption
        private static final int IV_SIZE = 12;
        private static final int TAG_BIT_LENGTH = 128;
        private static final int NONCE_SIZE = 16;
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
    }

}
