import java.io.Console;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
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
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Scanner;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public class SecureFileSharingServerWithEncryption {
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
    private static Path serverDownloadPath = Paths.get(System.getProperty("user.home"),
            "SecureFileSharingServerWithEncryption");
    private static Path serverTempPath = Paths.get(System.getProperty("java.io.tmpdir"),
            "SecureFileSharingServerWithEncryptionTemp");
    private static String ServerIPAdress;

    private static Scanner userInput = new Scanner(System.in);

    private static char[] passwordChars;
    private static char[] passwordHandShakeChars;
    private static byte[] passwordHandShakeBytes;

    private static byte[] EXPECTED_HANDSHAKE_HASH;

    private enum Progress {
        JUST_CONNECTED,
        READING_FILEDATA,
        READING_FILEDETAILS,
        READING_INFORMATION,
        READING_HANDSHAKE,
        READING_FILELIST,
        READING_FILE_NAME,
        WRITING_FILEDATA,
        WRITING_FILEDETAILS,
        WRITING_INFORMATION_DETAILS,
        WRITING_INFORMATION,
        WRITING_HANDSHAKE,
        WRITING_HANDSHAKE_SERVER_EC_PUBLIC_KEY,
        WRITING_FILELIST,
        VALID_HANDSHAKE,
        FILE_LIST_SAVED_TO_DISK
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

    private static final byte[] ENCODED_RSA_PUBLIC_KEY_BYTES = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+TEpsZJxq1bDlcGsy4a//RRq3MMfYeE+1J6yL9LiqCf0hbdBE4y86sQjbUquoYi6VpTITiw7uzMg3wzRmkqABFtcbOtzNEeHSpqgMv88YRDlPbVutsE4JAxmm6BkA2cLqIgjM6jbZRrnR5kwaw/jWFmhOpazNRH/c6HWQ3KLFAUc/ZXBchm69gFOdtGJ939rzE9zzpLo5t+lp/kAbXbdug98Geo7Nky5A3rv3ooFAaRgwovCCKQWoKGFKndgk1TootJuLBH+DaeQ+sjDhlAByrygwuV9pPS31r1lYoWQ8Ls5RclfVIDxJLpmOxjx0x1Qn6ixnQ7P75Uy6rA9s3PiwIDAQAB"
            .getBytes(StandardCharsets.UTF_8);
    private static final byte[] ENCODED_RSA_PRIVATE_KEY_BYTES = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC35MSmxknGrVsOVwazLhr/9FGrcwx9h4T7UnrIv0uKoJ/SFt0ETjLzqxCNtSq6hiLpWlMhOLDu7MyDfDNGaSoAEW1xs63M0R4dKmqAy/zxhEOU9tW62wTgkDGaboGQDZwuoiCMzqNtlGudHmTBrD+NYWaE6lrM1Ef9zodZDcosUBRz9lcFyGbr2AU520Yn3f2vMT3POkujm36Wn+QBtdt26D3wZ6js2TLkDeu/eigUBpGDCi8IIpBagoYUqd2CTVOii0m4sEf4Np5D6yMOGUAHKvKDC5X2k9LfWvWVihZDwuzlFyV9UgPEkumY7GPHTHVCfqLGdDs/vlTLqsD2zc+LAgMBAAECggEAHb2CzFIPRnFs44HRlJLlTPXPa4H8yCRtrlOlhefiKLZXgput/O9EsEG/OJvPIEFnTgQMo7fObaWgYbdpd360izRGVfgwKIq9awwcE15qNwkkAOh2onSfck3/p7EthQWed7BCwWL97U/uo4dx1hysXoodEWvxaWT/i52mKBHh246FiyEzzH9cpTPKtx7CgyDwq8kdORF7XD2a8DDMrUBBnc8JeTY9glOysnOx2y0GYAq2JMOIfTM/7JtNvBAnIGvnNhW6BDA01Bw2ubpeklBHzq69Jrv4AbjAGNyLcB47//75KYaASxseCnk0sEqcFfSe7oFZBVgI9ojR2H9LAXFsmQKBgQDIqioRfivmbg/Cg2QH4dGzqbG5KbJfwlzyBoLQeWqdNmmIHBA4cs2GS6q8Dv4ABgPgM5g5TNM2+64MqhctkIgmW7yCEAfFMVX82v3TWQvXNVv8pe3dgiBrXyfcD98xtNCymJckraUS7cThAZQ38DvWsQ0CR1gLoJlffTPVOIM0xwKBgQDqmqgwO9zqRNGDZa+aAqAcmIxRs/tQrY6pNq43WbQ3Xd+njIRMc1mj5X/M5+U1rO/Gstftvk+vKohiJdwbxlFe+/VZpJhaGF6Rwo6r+u5kz58XvUFN8lffvrFRNBX8P0PvK5ZZaix9ip6d6yYd3ap0OXiYMfzNtwNT6DJKF5mDHQKBgHT1shWGHCJwbmEq4kgx2F/G/h717dEg4bn0D5Vh38GIsJQz/0RXrfGj8v0wI95xoxqwF/72B3pZ0gXxshbN0n3BJKwOmejXK854+k+Q7HTg1h/5ux5MNYc/7GS5H5fCU451oEsxpzDUQ9f+apz8OnSVuAZm/SuxzRO6T1btXJSLAoGAdjaN7xgK/iTFKZ+Qd1tBUIdxlS3KweFiVFOQP6W80HVF4EhG1br9/T8EQbzL21sTyxyM/2f5APu+ky4elgQ9Nk5hV9U/S46iAHJ3r6MWgse3k5+yi1NFAiI1eQR025EJazecX9vHJU83E73MjBoI7N2UraPqjcHdNGd5B6qSmOUCgYEAozffWpGd0aCBAb2CJriEmGTwm4Yr+Yp0/yqWv9RFYP1PnFvKDY1vpaktankZTNeVwY2J0Cc1GNiUGnPn9V+nbLK/kPdqZ6Q8aTvln9vRYkRYl6KUdQetARiI8/mPXUK8Io8+eieHjVIN/SELQC+Lu66sUwjoQi3lu5Z3Zg6ECE4="
            .getBytes(StandardCharsets.UTF_8);
    private static RSAPublicKey serverRSAPublicKey;
    private static RSAPrivateKey serverRSAPrivateKey;

    private static ServerSocketChannel serverChannel;
    private static Selector selector;

    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[EXIT] Shutting down server...");
            serverShutdown();
        }));
        try {
            serverChannel = ServerSocketChannel.open();
        } catch (IOException e) {
            System.err.println("An error occured while trying to open server channel " + e.getMessage());
            return;
        }
        try {
            selector = Selector.open();
        } catch (IOException e) {
            System.err.println("An error occured while trying to open selector " + e.getMessage());
            return;
        }

        byte[] decodedRSAPublicKeyBytes;
        byte[] decodedRSAPrivateKeyBytes;
        try {
            decodedRSAPublicKeyBytes = Base64.getDecoder().decode(ENCODED_RSA_PUBLIC_KEY_BYTES);
            decodedRSAPrivateKeyBytes = Base64.getDecoder().decode(ENCODED_RSA_PRIVATE_KEY_BYTES);
            serverRSAPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(decodedRSAPublicKeyBytes));
            serverRSAPrivateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(decodedRSAPrivateKeyBytes));
        } catch (Exception e) {
            System.err.println("An error occured when loading the server rsa keys: " + e.getMessage());
            // secure wipe of RSA_PUBLIC_KEY_STRING, RSA_PRIVATE_KEY_STRING
            Arrays.fill(ENCODED_RSA_PUBLIC_KEY_BYTES, (byte) 0);
            Arrays.fill(ENCODED_RSA_PRIVATE_KEY_BYTES, (byte) 0);
            return;
        }

        // secure wipe of RSA_PUBLIC_KEY_STRING, RSA_PRIVATE_KEY_STRING,
        // rsaPublicKeyBytes, and rsaPrivateKeyBytes
        Arrays.fill(ENCODED_RSA_PUBLIC_KEY_BYTES, (byte) 0);
        Arrays.fill(ENCODED_RSA_PRIVATE_KEY_BYTES, (byte) 0);
        Arrays.fill(decodedRSAPublicKeyBytes, (byte) 0);
        Arrays.fill(decodedRSAPrivateKeyBytes, (byte) 0);

        if (Files.notExists(serverDownloadPath)) {
            try {
                Files.createDirectories(serverDownloadPath);
            } catch (IOException e) {
                System.err.println("An error occured when creating the download directory: " + e.getMessage());
                return;
            }
        }
        if (Files.notExists(serverTempPath)) {
            try {
                Files.createDirectories(serverTempPath);
            } catch (IOException e) {
                System.err.println("An error occured when creating the temp directory: " + e.getMessage());
                return;
            }
        }

        server();
    }

    private static void server() {
        System.out.println("Welcome to the server");

        try {
            serverChannel.configureBlocking(false);
            InetSocketAddress serverAddress = new InetSocketAddress("0.0.0.0", PORT);
            serverChannel.bind(serverAddress);
            printConnectionGuide();
            System.out.println("Please setup a password for the server.");
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

            MessageDigest passwordHandShakeDigest = MessageDigest.getInstance("SHA-256");
            EXPECTED_HANDSHAKE_HASH = passwordHandShakeDigest.digest(passwordHandShakeBytes);

            // secure wipe of passwordchars, passwordHandShakeChars,
            // passwordHandShakeBytes and bufferB array
            Arrays.fill(passwordChars, ' ');
            Arrays.fill(passwordHandShakeChars, ' ');
            Arrays.fill(passwordHandShakeBytes, (byte) 0);

            System.out.println("\nWaiting for connections..."); // remove this and also as an attachment
            serverChannel.register(selector, SelectionKey.OP_ACCEPT);

            while (true) {
                if (selector.select() == 0)
                    continue;

                Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();

                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    if (!key.isValid())
                        continue;

                    if (key.isAcceptable()) {
                        ServerSocketChannel readyServer = (ServerSocketChannel) key.channel();
                        SocketChannel clientChannel = readyServer.accept();
                        clientChannel.configureBlocking(false);
                        CurrentSession currentClientSession = new CurrentSession();
                        currentClientSession.generateServerBaseIV();
                        currentClientSession.progressState = Progress.JUST_CONNECTED;
                        // only register read events. write events will be added only when needed
                        clientChannel.register(selector, SelectionKey.OP_READ, currentClientSession);
                        System.out.println("Client " + clientChannel.getRemoteAddress() + " just connected");
                    }

                    if (key.isReadable()) {
                        SocketChannel readyClient = (SocketChannel) key.channel();
                        CurrentSession keySession = (CurrentSession) key.attachment();
                        try {

                            switch (keySession.progressState) {
                                case Progress.JUST_CONNECTED, Progress.READING_HANDSHAKE -> {
                                    // Kills any connection that is not authenticated in 12 seconds
                                    long currentTime = System.currentTimeMillis();
                                    if (currentTime - keySession.connectTime > 12000) {
                                        System.err.println("Client " + readyClient.getRemoteAddress()
                                                + " took too long to authenticate. disconnecting...");
                                        cancelKey(key);
                                        continue;
                                    }
                                    readHandShake(key);
                                }
                                case Progress.WRITING_HANDSHAKE, Progress.WRITING_HANDSHAKE_SERVER_EC_PUBLIC_KEY -> {
                                    writeHandShake(key);
                                }
                                case Progress.VALID_HANDSHAKE -> {
                                    if (keySession.command == NO_COMMAND && keySession.encCommandReceiveBuffer
                                            .position() != keySession.encCommandReceiveBuffer.capacity()) {
                                        int bytesRead;
                                        bytesRead = readyClient.read(keySession.encCommandReceiveBuffer);
                                        if (bytesRead < 0) {
                                            System.err.println("Client " + readyClient.getRemoteAddress()
                                                    + " disconnected");
                                            cancelKey(key);
                                            continue;
                                        }
                                        if (keySession.encCommandReceiveBuffer
                                                .position() == keySession.encCommandReceiveBuffer.capacity()) {
                                            byte[] commandBytes = new byte[keySession.commandReceiveBuffer.capacity()];
                                            commandBytes = keySession
                                                    .rsaDecrypt(keySession.encCommandReceiveBuffer.array());
                                            keySession.commandReceiveBuffer.clear().put(commandBytes).flip();
                                            keySession.command = keySession.commandReceiveBuffer.getInt();
                                        }
                                    }
                                    if (keySession.command == EXIT) {
                                        System.out.println("Client " + readyClient.getRemoteAddress()
                                                + " disconnected");
                                        cancelKey(key);
                                        continue;
                                    }
                                    if (keySession.command == NO_COMMAND) {
                                        // do nothing
                                        continue;
                                    }
                                    if (keySession.command == FILE_SEND_REQUEST) {
                                        serverSendFile(key);
                                    }
                                    if (keySession.command == FILE_UPLOAD_REQUEST) {
                                        serverReceiveFile(key);
                                    }
                                    if (keySession.command == FILE_LIST_REQUEST) {
                                        serverSendFilesList(key);
                                    }
                                    if (keySession.command != NO_COMMAND && keySession.command != FILE_SEND_REQUEST
                                            && keySession.command != FILE_UPLOAD_REQUEST
                                            && keySession.command != FILE_LIST_REQUEST) {
                                        // Invalid command, cancel this key and move to the next
                                        System.err.println("Invalid command; client " + readyClient.getRemoteAddress()
                                                + " may have closed the connection...");
                                        cancelKey(key);
                                        continue;
                                    }
                                }
                                case Progress.WRITING_FILEDETAILS, Progress.WRITING_FILEDATA -> {
                                    serverSendFile(key);
                                }
                                case Progress.READING_FILEDETAILS, Progress.READING_FILEDATA -> {
                                    serverReceiveFile(key);
                                }
                                case Progress.FILE_LIST_SAVED_TO_DISK, Progress.WRITING_FILELIST -> {
                                    serverSendFilesList(key);
                                }

                            }
                        } catch (Exception e) {
                            System.out.println("An error occured with client " + readyClient.getRemoteAddress());
                            cancelKey(key);
                            continue; // go to the next key
                        }

                    }
                    if (key.isWritable()) {
                        SocketChannel readyClient = (SocketChannel) key.channel();
                        CurrentSession keySession = (CurrentSession) key.attachment();
                        try {

                            switch (keySession.progressState) {
                                case Progress.WRITING_HANDSHAKE, Progress.WRITING_HANDSHAKE_SERVER_EC_PUBLIC_KEY -> {
                                    writeHandShake(key);
                                }
                                case Progress.FILE_LIST_SAVED_TO_DISK, Progress.WRITING_FILELIST -> {
                                    serverSendFilesList(key);
                                }
                                case Progress.WRITING_FILEDETAILS, Progress.WRITING_FILEDATA -> {
                                    serverSendFile(key);
                                }
                                case Progress.WRITING_INFORMATION, Progress.WRITING_INFORMATION_DETAILS -> {
                                    if (keySession.command == FILE_SEND_REQUEST) {
                                        serverSendFile(key);
                                    }
                                }
                                case Progress.VALID_HANDSHAKE -> {
                                    if (keySession.command == FILE_SEND_REQUEST) {
                                        serverSendFile(key);
                                    }
                                    if (keySession.command == FILE_UPLOAD_REQUEST) {
                                        serverReceiveFile(key);
                                    }
                                    if (keySession.command == FILE_LIST_REQUEST) {
                                        serverSendFilesList(key);
                                    }
                                }
                            }
                        } catch (Exception e) {
                            System.out.println("An error occured with client " + readyClient.getRemoteAddress());
                            cancelKey(key);
                            continue; // go to the next key
                        }
                    }
                }
            }

        } catch (Exception e) {
            System.out.println("An error occured with the server: " + e.getMessage());
        }

    }

    private static void readHandShake(SelectionKey key) throws Exception {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
        try {
            /*
             * Read the first 256 bytes of the encrypted handshake
             * Decrypt this using the server rsa private key
             * The decrypted bytes contain the following
             * bytes 0-3: length of the remaining bytes after the first 256
             * bytes 4-19: nonce
             * remaining bytes: the client iv and the client ecdh public key
             */
            if (keySession.progressState == Progress.JUST_CONNECTED) {
                int bytesRead;
                bytesRead = clientChannel.read(keySession.encHandShakeReceiveLengthBuffer);
                if (bytesRead < 0) {
                    System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                    cancelKey(key);
                    return;
                } else if (bytesRead > 0 && keySession.encHandShakeReceiveLengthBuffer
                        .position() != keySession.encHandShakeReceiveLengthBuffer.capacity()) {
                    return;
                } else if (bytesRead > 0 && keySession.encHandShakeReceiveLengthBuffer
                        .position() == keySession.encHandShakeReceiveLengthBuffer.capacity()) {
                    byte[] decrypted = keySession.rsaDecrypt(keySession.encHandShakeReceiveLengthBuffer.array());
                    ByteBuffer decryptedBuffer = ByteBuffer.wrap(decrypted);
                    int lengthOfBytesAfter256 = decryptedBuffer.getInt();
                    keySession.handShakeReceiveLengthBuffer.clear().putInt(lengthOfBytesAfter256).flip();
                    decryptedBuffer.get(keySession.nonceArray);
                    decryptedBuffer.get(keySession.clientIV);
                    keySession.setupClientBaseIV(keySession.clientIV);
                    byte[] ecdhBytes = new byte[decryptedBuffer.remaining()];
                    decryptedBuffer.get(ecdhBytes);
                    byte[] ecdhDecodedBytes = Base64.getDecoder().decode(ecdhBytes);
                    X509EncodedKeySpec clientECPublicKeySpec = new X509EncodedKeySpec(ecdhDecodedBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    try {
                        keySession.clientPublicKey = (ECPublicKey) keyFactory.generatePublic(clientECPublicKeySpec);
                    } catch (Exception e) {
                        System.err.println("Could not generate ec public key for " + clientChannel.getRemoteAddress()
                                + "try recoonecting...");
                        cancelKey(key);
                        return;
                    }

                    // secure wipe of decrypted, ecdhBytes, ecdhDecodedBytes
                    Arrays.fill(decrypted, (byte) 0);
                    Arrays.fill(ecdhBytes, (byte) 0);
                    Arrays.fill(ecdhDecodedBytes, (byte) 0);

                    // set up server ec keys and shared secret
                    ECPublicKey clientECPubKey = (ECPublicKey) keySession.clientPublicKey;
                    ECParameterSpec ecParams = clientECPubKey.getParams();
                    KeyPairGenerator serverKpg = KeyPairGenerator.getInstance("EC");
                    serverKpg.initialize(ecParams);
                    KeyPair serverKP = serverKpg.generateKeyPair();

                    keySession.serverECPublicKey = (ECPublicKey) serverKP.getPublic();
                    keySession.serverECPrivateKey = (ECPrivateKey) serverKP.getPrivate();
                    try {
                        keySession.secretKeySetup();
                    } catch (Exception e) {
                        System.err.println("Could not generate secret key for " + clientChannel.getRemoteAddress()
                                + "try reconnecting...");
                        cancelKey(key);
                        return;
                    }
                    keySession.encHandShakeReceiveBuffer = ByteBuffer
                            .allocate(keySession.handShakeReceiveLengthBuffer.getInt());
                    keySession.progressState = Progress.WRITING_HANDSHAKE_SERVER_EC_PUBLIC_KEY;
                    writeHandShake(key); // this will only send the server ecdh public key for now.
                }
            }

            if (keySession.progressState == Progress.READING_HANDSHAKE) {
                int bytesRead;
                /*
                 * the server can only decrypt this if it succeessfully
                 * decrypted the first 256 bytes in the previous step and got the client ecdh
                 * public key to generate the shared secret key
                 * 
                 * the decrypted handshake contains
                 * the handshakestringlength at 16 -> 23,
                 * rsa public key length at 24 -> 27,
                 * the handshakestring at 28 -> 28 + handshakestringlength,
                 * the client's rsa public key at the remaining bytes
                 */
                if (keySession.encHandShakeReceiveBuffer.position() != keySession.encHandShakeReceiveBuffer
                        .capacity()) {
                    bytesRead = clientChannel.read(keySession.encHandShakeReceiveBuffer);
                    if (bytesRead < 0) {
                        System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                        cancelKey(key);
                        return;
                    } else if (bytesRead > 0 && keySession.encHandShakeReceiveBuffer
                            .position() == keySession.encHandShakeReceiveBuffer.capacity()) {
                        System.out.println("Handshake read from client: " + clientChannel.getRemoteAddress());
                        try {
                            keySession.encHandShakeReceiveBuffer.flip();
                            keySession.decryptedHandShake = ByteBuffer
                                    .wrap(keySession.decrypt(keySession.encHandShakeReceiveBuffer.array()));
                        } catch (Exception e) {
                            System.err.println(
                                    clientChannel.getRemoteAddress() + " is not a valid client. disconnecting...");
                            cancelKey(key);
                            return;
                        }
                        byte[] decryptedHandshakeStringLengthArray = new byte[4];
                        keySession.decryptedHandShake.get(decryptedHandshakeStringLengthArray);
                        int handShakeStringLength = ByteBuffer.wrap(decryptedHandshakeStringLengthArray).getInt();
                        byte[] clientRSAPublicKeyLengthArr = new byte[4];
                        keySession.decryptedHandShake.get(clientRSAPublicKeyLengthArr);
                        int clientRSAPublicKeyLength = ByteBuffer.wrap(clientRSAPublicKeyLengthArr).getInt();
                        byte[] handshakeCharArray = new byte[handShakeStringLength];
                        keySession.decryptedHandShake.get(handshakeCharArray);
                        byte[] RECEIVED_HANDSHAKE_HASH = MessageDigest.getInstance("SHA-256")
                                .digest(handshakeCharArray);
                        if (!MessageDigest.isEqual(RECEIVED_HANDSHAKE_HASH, EXPECTED_HANDSHAKE_HASH)) {
                            System.err.println("Client " + clientChannel.getRemoteAddress()
                                    + " handshake hash does not match. disconnecting...");
                            cancelKey(key);
                            return;
                        }
                        byte[] clientRSAPublicKeyArray = new byte[clientRSAPublicKeyLength];
                        keySession.decryptedHandShake.get(clientRSAPublicKeyArray);
                        byte[] clientRSAPublicKeyDecodedBytes = Base64.getDecoder().decode(clientRSAPublicKeyArray);
                        X509EncodedKeySpec clientRSAPublicKeySpec = new X509EncodedKeySpec(
                                clientRSAPublicKeyDecodedBytes);
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        try {
                            keySession.clientRSAPublicKey = (RSAPublicKey) keyFactory
                                    .generatePublic(clientRSAPublicKeySpec);
                        } catch (Exception e) {
                            System.err.println(
                                    "Could not generate handshake public key for " + clientChannel.getRemoteAddress()
                                            + " try reconnecting...");
                            cancelKey(key);
                            return;
                        }

                        // send the next 256 bytes encrypted and containing the nonce and iv

                        int bufferCapacity = keySession.NONCE_SIZE + keySession.IV_SIZE;
                        ByteBuffer handShakeToEncrypt = ByteBuffer.allocate(bufferCapacity);
                        handShakeToEncrypt.put(keySession.nonceArray);
                        handShakeToEncrypt.put(keySession.serverIV);
                        handShakeToEncrypt.flip();
                        try {
                            keySession.encHandShakeSendBuffer = ByteBuffer
                                    .wrap(keySession.rsaEncrypt(handShakeToEncrypt.array()));
                        } catch (Exception e) {
                            System.err.println("Could not encrypt handshake for " + clientChannel.getRemoteAddress()
                                    + " try recoonecting...");
                            cancelKey(key);
                            return;
                        }
                        System.out.println("Client " + clientChannel.getRemoteAddress()
                                + " authenticated.");
                        keySession.progressState = Progress.WRITING_HANDSHAKE;
                        writeHandShake(key);

                    }
                }

            }
        } catch (Exception e) {
            System.err.println("An error occured with the client " + clientChannel.getRemoteAddress());
            return;
        }

    }

    private static void writeHandShake(SelectionKey key) throws Exception {
        long bytesWritten;
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
        if (keySession.progressState == Progress.WRITING_HANDSHAKE_SERVER_EC_PUBLIC_KEY) {
            try {
                // the server already received the client's EC public Key in encrypted form
                // so it's safe to send the server's EC public key in unencrypted form
                // send the length of the key and then the actual key
                byte[] serverECBase64;
                if (keySession.serverECPublicKeyBuffer == null) {
                    serverECBase64 = Base64.getEncoder().encode(keySession.serverECPublicKey.getEncoded());
                    int ECLength = serverECBase64.length;
                    keySession.serverECPublicKeyBuffer = ByteBuffer.allocate(4 + ECLength);
                    keySession.serverECPublicKeyBuffer.putInt(ECLength);
                    keySession.serverECPublicKeyBuffer.put(serverECBase64);
                    keySession.serverECPublicKeyBuffer.flip();
                    // secure wipe of serverECBase64
                    Arrays.fill(serverECBase64, (byte) 0);
                }
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                bytesWritten = clientChannel.write(keySession.serverECPublicKeyBuffer);
                if (bytesWritten < 0) {
                    System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                    cancelKey(key);
                } else if (bytesWritten > 0 && !keySession.serverECPublicKeyBuffer.hasRemaining()) {
                    keySession.serverECPublicKeyBuffer.clear();
                    // secure wipe of keySession.serverECPublicKeyBuffer
                    Arrays.fill(keySession.serverECPublicKeyBuffer.array(), (byte) 0);

                    key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                    keySession.progressState = Progress.READING_HANDSHAKE;
                } else if (bytesWritten == 0) {
                    key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                }
            } catch (Exception e) {
                System.err.println("An error occured with while sending ec public key to client "
                        + clientChannel.getRemoteAddress());
                return;
            }
        }

        if (keySession.progressState == Progress.WRITING_HANDSHAKE) {
            try {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                bytesWritten = clientChannel.write(keySession.encHandShakeSendBuffer);
                if (bytesWritten < 0) {
                    System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                    cancelKey(key);
                } else if (bytesWritten > 0 && !keySession.encHandShakeSendBuffer.hasRemaining()) {
                    keySession.encHandShakeSendBuffer.clear();
                    key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                    keySession.progressState = Progress.VALID_HANDSHAKE;
                } else if (bytesWritten == 0) {
                    key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                }
            } catch (Exception e) {
                System.err.println("An error occured with while sending nonce and iv to client "
                        + clientChannel.getRemoteAddress());
                return;
            }
        }

    }

    /*
     * Sends the file list to the client
     * First, the command and the encrypted file list length are sent
     * Then, the encrypted file list is sent
     */
    private static void serverSendFilesList(SelectionKey key) throws Exception {
        CurrentSession keySession = (CurrentSession) key.attachment();
        SocketChannel clientChannel = (SocketChannel) key.channel();
        if (keySession.fileChannel == null || !keySession.fileChannel.isOpen()) {
            System.out.println("Client " + clientChannel.getRemoteAddress() + " requested file list");
            if (keySession.progressState != Progress.FILE_LIST_SAVED_TO_DISK) {
                keySession.fileListTempFile = serverTempPath.resolve("temp_file_list" + TEMPFILENUMBER++);
                AsynchronousFileChannel asyncFileChannel = AsynchronousFileChannel.open(
                        keySession.fileListTempFile, StandardOpenOption.WRITE,
                        StandardOpenOption.CREATE);
                try (Stream<Path> files = Files.list(serverDownloadPath)) {
                    String fileList = "No files available on server";
                    if (files.filter(Files::isRegularFile).findAny().isPresent()) {
                        try (Stream<Path> filesList = Files.list(serverDownloadPath)) {
                            fileList = filesList.filter(Files::isRegularFile).map(Path::getFileName).map(Path::toString)
                                    .collect(Collectors.joining("\n"));
                        } catch (Exception e) {
                            System.err.println("An error occured while trying to get file list " + e.getMessage());
                        }
                    }

                    byte[] fileListBytes = fileList.getBytes(StandardCharsets.UTF_8);
                    byte[] encryptedFileListBytes = keySession.encrypt(fileListBytes);
                    int prevOps = key.interestOps();
                    key.interestOps(0);
                    asyncFileChannel.write(ByteBuffer.wrap(encryptedFileListBytes), 0, key,
                            new CompletionHandler<Integer, SelectionKey>() {
                                @Override
                                public void completed(Integer result, SelectionKey attachment) {
                                    // restore read and enable write
                                    CurrentSession keySession = (CurrentSession) attachment.attachment();
                                    try {
                                        keySession.fileChannel = FileChannel.open(keySession.fileListTempFile,
                                                StandardOpenOption.READ);
                                        keySession.progressState = Progress.FILE_LIST_SAVED_TO_DISK;
                                    } catch (Exception e) {
                                        System.out.println("An error occured while opening file channel on File: "
                                                + keySession.fileListTempFile.getFileName().toString());
                                    }
                                    attachment.interestOps(prevOps | SelectionKey.OP_WRITE);
                                    attachment.selector().wakeup();
                                }

                                @Override
                                public void failed(Throwable exc, SelectionKey attachment) {
                                    attachment.interestOps(prevOps);
                                    System.err.println(
                                            "An error occured while writing fileList to file: " + exc.getMessage());
                                }
                            });

                } catch (Exception e) {
                    System.err.println(
                            "An error occured while trying to check file presence for file list " + e.getMessage());
                }
            }
        }
        if (keySession.progressState == Progress.FILE_LIST_SAVED_TO_DISK) {
            if (keySession.fileChannel == null || !keySession.fileChannel.isOpen())
                return;
            long bytesWritten;
            if (keySession.fileListInfoHeaderBuffer == null) {
                keySession.fileListInfoHeaderBuffer = ByteBuffer.allocate(4 + 8);
                keySession.fileListInfoHeaderBuffer.putInt(FILE_LIST);
                keySession.fileListInfoHeaderBuffer.putLong(keySession.fileChannel.size());
                keySession.fileListInfoHeaderBuffer.flip();
                try {
                    keySession.encFileListInfoHeaderBuffer = ByteBuffer
                            .wrap(keySession.rsaEncrypt(keySession.fileListInfoHeaderBuffer.array()));
                } catch (Exception e) {
                    System.err.println("An error occured while encrypting the fie list info header");
                    cleanUpCurrentSessionObj(keySession);
                    return;
                }
            }
            bytesWritten = clientChannel.write(keySession.encFileListInfoHeaderBuffer);
            if (bytesWritten < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
            } else if (bytesWritten > 0 && keySession.encFileListInfoHeaderBuffer
                    .position() == keySession.encFileListInfoHeaderBuffer.capacity()) {
                keySession.progressState = Progress.WRITING_FILELIST;
            } else if (bytesWritten == 0) {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
            }

        }
        if (keySession.progressState == Progress.WRITING_FILELIST) {
            if (keySession.fileChannel == null || !keySession.fileChannel.isOpen())
                return;
            long bytesWritten;
            bytesWritten = keySession.fileChannel.transferTo(keySession.c2cTransferCurrentPosition,
                    keySession.fileChannel.size(), clientChannel);
            if (bytesWritten < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
            } else if (bytesWritten > 0) {
                keySession.c2cTransferCurrentPosition += bytesWritten;
                if (keySession.c2cTransferCurrentPosition == keySession.fileChannel.size()) {
                    System.out.println("File list sent to client " + clientChannel.getRemoteAddress());
                    keySession.fileChannel.close();
                    key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                    Files.deleteIfExists(keySession.fileListTempFile);
                    resetCurrentSessionObj(keySession);
                    return;
                }
            } else if (bytesWritten == 0) {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
            }
        }
    }

    private static void serverSendFile(SelectionKey key) throws Exception {
        int bytesRead;
        long bytesWritten;
        long bytesReadFromFile;
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
        if (keySession.encFileNameLengthBuffer.position() < keySession.encFileNameLengthBuffer.capacity()) {
            bytesRead = clientChannel.read(keySession.encFileNameLengthBuffer);
            if (bytesRead < 0) {
                cancelKey(key);
                return;
            } else if (bytesRead > 0
                    && keySession.encFileNameLengthBuffer.position() < keySession.encFileNameLengthBuffer
                            .capacity()) {
                return;
            } else if (bytesRead > 0
                    && keySession.encFileNameLengthBuffer.position() == keySession.encFileNameLengthBuffer.capacity()) {
                try {
                    keySession.decFileNameLengthBuffer = ByteBuffer
                            .wrap(keySession.rsaDecrypt(keySession.encFileNameLengthBuffer.array()));
                    keySession.decFileNameLength = keySession.decFileNameLengthBuffer.getInt();
                    keySession.encFileNameBuffer = ByteBuffer.allocate(keySession.decFileNameLength);
                    if (keySession.decFileNameLength <= 0) {
                        System.err.println("Invalid file name length for client " + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                    keySession.progressState = Progress.READING_FILE_NAME;

                } catch (Exception e) {
                    System.err.println("An error occured while decrypting file name length for client "
                            + clientChannel.getRemoteAddress());
                    cancelKey(key);
                    return;
                }
            }

        }
        if (keySession.progressState == Progress.READING_FILE_NAME) {

            bytesRead = clientChannel.read(keySession.encFileNameBuffer);
            if (bytesRead < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
                return;
            } else if (bytesRead > 0
                    && keySession.encFileNameBuffer.position() < keySession.encFileNameBuffer.capacity()) {
                return;
            } else if (bytesRead > 0
                    && keySession.encFileNameBuffer.position() == keySession.encFileNameBuffer.capacity()) {
                keySession.encFileNameBuffer.flip();
                try {
                    keySession.decFileNameBuffer = ByteBuffer
                            .wrap(keySession.decrypt(keySession.encFileNameBuffer.array()));
                    keySession.fileName = new String(keySession.decFileNameBuffer.array(), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    System.err.println("An error occured while decrypting file name for client "
                            + clientChannel.getRemoteAddress());
                    cancelKey(key);
                    return;
                }
                if (keySession.fileName.isEmpty()) {
                    System.err.println("Invalid file name for client " + clientChannel.getRemoteAddress());
                    resetCurrentSessionObj(keySession);
                    ;
                    return;
                }
                keySession.fileToSend = serverDownloadPath.resolve(keySession.fileName);
                if (Files.notExists(keySession.fileToSend)) {
                    System.out.println("Client " + clientChannel.getRemoteAddress() + " requested file "
                            + keySession.fileName + " that does not exist");
                    keySession.progressState = Progress.WRITING_INFORMATION_DETAILS;
                } else if (Files.exists(keySession.fileToSend) && keySession.unEncFileDetails256 == null) {
                    System.out.println("Client " + clientChannel.getRemoteAddress() + " requested file "
                            + keySession.fileName + " that exists");
                    // command at the first 4 bytes
                    // file size at the next 8 bytes
                    // file name length at the next 4 bytes
                    keySession.unEncFileDetails256 = ByteBuffer.allocate(4 + 8 + 4);
                    keySession.unEncFileDetails256.putInt(FILE_DOWNLOAD);
                    keySession.fileSize = Files.size(keySession.fileToSend);
                    keySession.unEncFileDetails256.putLong(keySession.fileSize);

                    // get the file name, encrypt it and get the length of the encrypted file name
                    keySession.fileName = keySession.fileToSend.getFileName().toString();
                    byte[] fileNameBytes = keySession.fileName.getBytes(StandardCharsets.UTF_8);
                    byte[] encFileNameBytes;
                    try {
                        encFileNameBytes = keySession.encrypt(fileNameBytes);
                    } catch (Exception e) {
                        System.err.println("An error occured while encrypting file name for client "
                                + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                    keySession.encFileNameBuffer = ByteBuffer.wrap(encFileNameBytes);
                    keySession.unEncFileDetails256.putInt(encFileNameBytes.length);
                    keySession.unEncFileDetails256.flip();
                    try {
                        keySession.encFileDetails256 = ByteBuffer
                                .wrap(keySession.rsaEncrypt(keySession.unEncFileDetails256.array()));
                    } catch (Exception e) {
                        System.err.println("An error occured while encrypting file details for client "
                                + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                    keySession.fileDetailsBufferArr = new ByteBuffer[] { keySession.encFileDetails256,
                            keySession.encFileNameBuffer };

                    try {
                        keySession.fileChannel = FileChannel.open(keySession.fileToSend, StandardOpenOption.READ);
                        keySession.fileSize = keySession.fileChannel.size();
                    } catch (Exception e) {
                        System.err.println("An error occured while opening fileChannel on the file : "
                                + keySession.fileName + " for client " + clientChannel.getRemoteAddress());
                        return; // exit the method and try again
                    }

                    keySession.progressState = Progress.WRITING_FILEDETAILS;
                    key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                }
            }

        }

        if (keySession.progressState == Progress.WRITING_INFORMATION_DETAILS) {
            keySession.information = "file \"" + keySession.fileName
                    + "\" does not exist";
            if (keySession.encInformationDetailsBuffer == null) {
                try {
                    keySession.encInformationBuffer = ByteBuffer
                            .wrap(keySession.encrypt(keySession.information.getBytes(StandardCharsets.UTF_8)));
                    keySession.informationDetailsBuffer = ByteBuffer.allocate(4 + 4);
                    keySession.informationDetailsBuffer.putInt(INFORMATION);
                    keySession.informationDetailsBuffer.putInt(keySession.encInformationBuffer.capacity());
                    keySession.informationDetailsBuffer.flip();
                    keySession.encInformationDetailsBuffer = ByteBuffer
                            .wrap(keySession.rsaEncrypt(keySession.informationDetailsBuffer.array()));

                } catch (Exception e) {
                    System.err.println("An error occured while encrypting information details for client "
                            + clientChannel.getRemoteAddress());
                    cancelKey(key);
                    return;
                }
            }
            // write the encrypted information details
            // 256 bytes
            bytesWritten = clientChannel.write(keySession.encInformationDetailsBuffer);
            if (bytesWritten < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
                return;
            } else if (bytesWritten > 0 && keySession.encInformationDetailsBuffer.hasRemaining()) {
                return; // continue writing
            } else if (bytesWritten > 0 && !keySession.encInformationDetailsBuffer.hasRemaining()) {
                keySession.progressState = Progress.WRITING_INFORMATION;
            } else if (bytesWritten == 0) {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                return; // continue writing
            }

        }
        if (keySession.progressState == Progress.WRITING_INFORMATION) {
            // write the encrypted information string
            bytesWritten = clientChannel.write(keySession.encInformationBuffer);
            if (bytesWritten < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
                return;
            } else if (bytesWritten > 0 && keySession.encInformationBuffer.hasRemaining()) {
                return; // continue writing
            } else if (bytesWritten > 0 && !keySession.encInformationBuffer.hasRemaining()) {
                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                System.out.println("Sent information to client "
                        + clientChannel.getRemoteAddress() + ": " + keySession.information);
                resetCurrentSessionObj(keySession);
                return;
            } else if (bytesWritten == 0) {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                return; // continue writing
            }
        }

        if (keySession.progressState == Progress.WRITING_FILEDETAILS) {
            bytesWritten = clientChannel.write(keySession.fileDetailsBufferArr);
            if (bytesWritten < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
                return;
            } else if (bytesWritten > 0 && !keySession.encFileNameBuffer.hasRemaining()) {
                keySession.progressState = Progress.WRITING_FILEDATA;

            } else if (bytesWritten == 0) {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
            }
        }
        if (keySession.progressState == Progress.WRITING_FILEDATA) {
            if (keySession.fileChannel == null || !keySession.fileChannel.isOpen()) {
                try {
                    keySession.fileChannel = FileChannel.open(keySession.fileToSend, StandardOpenOption.READ);
                    keySession.fileSize = keySession.fileChannel.size();
                } catch (Exception e) {
                    System.err.println("An error occured while opening fileChannel on the file : "
                            + keySession.fileName + " for client " + clientChannel.getRemoteAddress());
                    return; // exit the method and try again
                }
            }
            if (keySession.fileChannel.isOpen()) {
                if (keySession.fileChannelPosition < keySession.fileSize) {
                    if (keySession.chunkStatus == ChunkProgress.DEFAULT
                            || keySession.chunkStatus == ChunkProgress.CHUNK_SENT) {
                        bytesReadFromFile = keySession.fileChannel.read(
                                keySession.unencryptedFileChunkBuffer, keySession.fileChannelPosition);
                        if (bytesReadFromFile < 0) {
                            return; // exit the method and try again
                        }

                        keySession.fileChannelPosition += bytesReadFromFile;
                        keySession.unencryptedFileChunkBuffer.flip();
                        byte[] validBytes = new byte[keySession.unencryptedFileChunkBuffer.remaining()];
                        keySession.unencryptedFileChunkBuffer.get(validBytes);
                        keySession.unencryptedFileChunkBuffer.clear();
                        byte[] encFileChunkBytes;
                        try {
                            encFileChunkBytes = keySession
                                    .encrypt(validBytes);
                        } catch (Exception e) {
                            System.err.println("An error occured while encrypting the file chunk for client "
                                    + clientChannel.getRemoteAddress());
                            cancelKey(key);
                            return;
                        }
                        keySession.directFileChunkBuffer.clear().put(encFileChunkBytes).flip();
                        keySession.chunkLengthBuffer.clear().putInt(keySession.directFileChunkBuffer.remaining())
                                .flip();
                        byte[] encLengthBytes;
                        try {
                            encLengthBytes = keySession.rsaEncrypt(keySession.chunkLengthBuffer.array());
                        } catch (Exception e) {
                            System.err.println(
                                    "An error occured while encrypting the length of the file chunk for client "
                                            + clientChannel.getRemoteAddress());
                            cancelKey(key);
                            return;
                        }
                        keySession.encChunkLengthBuffer.clear().put(encLengthBytes).flip();

                        /*
                         * Encrypted chunk length at the first 256 bytes
                         * Encrypted chunk at the remaining bytes
                         */
                        keySession.encChunkLengthAndDataArr = new ByteBuffer[] {
                                keySession.encChunkLengthBuffer,
                                keySession.directFileChunkBuffer
                        };

                        keySession.chunkStatus = ChunkProgress.SENDING_CHUNK;
                    }
                }
                if (keySession.chunkStatus == ChunkProgress.SENDING_CHUNK) {
                    bytesWritten = clientChannel.write(keySession.encChunkLengthAndDataArr);
                    if (bytesWritten < 0) {
                        System.err.println(
                                "Client " + clientChannel.getRemoteAddress() + " closed the connection");
                        cancelKey(key);
                        return;
                    } else if (bytesWritten > 0 && !keySession.directFileChunkBuffer.hasRemaining()) {
                        if (keySession.fileChannelPosition >= keySession.fileSize) {
                            keySession.chunkStatus = ChunkProgress.ALL_CHUNK_SENT;
                        } else {
                            keySession.chunkStatus = ChunkProgress.CHUNK_SENT;
                            return;
                        }
                    } else if (bytesWritten == 0) {
                        key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                    }
                }
                if (keySession.chunkStatus == ChunkProgress.ALL_CHUNK_SENT) {
                    System.out.println("Sent file \"" + keySession.fileName + "\" to client "
                            + clientChannel.getRemoteAddress());
                    key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                    resetCurrentSessionObj(keySession);
                    return;
                }

            }
        }

    }

    private static void serverReceiveFile(SelectionKey key) throws Exception {
        int bytesRead;
        long bytesWrittenToFile;
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
        // changes the progress state only once when this function is first executed
        if (keySession.progressState == Progress.VALID_HANDSHAKE) {
            keySession.progressState = Progress.READING_FILEDETAILS;
        }

        if (keySession.progressState == Progress.READING_FILEDETAILS) {
            if (keySession.unEncFileDetails256 == null) {
                bytesRead = clientChannel.read(keySession.encFileDetails256);
                if (bytesRead < 0) {
                    System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                    cancelKey(key);
                    return;
                } else if (bytesRead > 0
                        && keySession.encFileDetails256.position() < keySession.encFileDetails256.capacity()) {
                    return; // continue reading
                } else if (bytesRead > 0
                        && keySession.encFileDetails256.position() == keySession.encFileDetails256.capacity()) {
                    try {
                        keySession.unEncFileDetails256 = ByteBuffer
                                .wrap(keySession.rsaDecrypt(keySession.encFileDetails256.array()));
                        keySession.fileSize = keySession.unEncFileDetails256.getLong();
                        keySession.fileNameLength = keySession.unEncFileDetails256.getInt();
                        keySession.encFileNameBuffer = ByteBuffer.allocate(keySession.fileNameLength);
                    } catch (Exception e) {
                        System.err.println("An error occured while decrypting file details for client "
                                + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                } else if (bytesRead == 0) {
                    return; // continue reading
                }
            }

            if (keySession.fileNameLength > 0 && keySession.fileName.isBlank()) {
                bytesRead = clientChannel.read(keySession.encFileNameBuffer);
                if (bytesRead < 0) {
                    System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                    cancelKey(key);
                    return;
                } else if (bytesRead > 0 && keySession.encFileNameBuffer.position() != keySession.fileNameLength) {
                    return;
                } else if (bytesRead > 0 && keySession.encFileNameBuffer.position() == keySession.fileNameLength) {
                    try {
                        keySession.fileNameBuffer = ByteBuffer
                                .wrap(keySession.decrypt(keySession.encFileNameBuffer.array()));
                        keySession.fileName = new String(keySession.fileNameBuffer.array(), StandardCharsets.UTF_8);
                        System.out.println("Client " + clientChannel.getRemoteAddress() + " wants to upload file: "
                                + keySession.fileName);
                    } catch (Exception e) {
                        System.err.println("An error occured while decrypting the file name for client "
                                + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                } else
                    return;

            }

            if (!keySession.fileName.isBlank() && keySession.fileSize > 0) {
                keySession.filePath = serverDownloadPath.resolve(keySession.fileName);
                int lastDotIndex = keySession.fileName.lastIndexOf(".");
                keySession.fileExtension = keySession.fileName.substring(lastDotIndex);
                keySession.fileNameWithoutExtension = keySession.fileName.substring(0, lastDotIndex);
                if (keySession.progressState != Progress.READING_FILEDATA) {
                    int counter = 0;
                    while (true) {
                        if (Files.exists(keySession.filePath)) {
                            counter++;

                            String regex = "\\(\\d+\\)$";
                            String cleanName = keySession.fileNameWithoutExtension.replaceAll(regex, "");
                            keySession.fileNameWithoutExtension = cleanName;

                            keySession.filePath = serverDownloadPath.resolve(
                                    keySession.fileNameWithoutExtension + "(" + counter + ")"
                                            + keySession.fileExtension);

                            keySession.fileName = keySession.filePath.getFileName().toString();

                            int lastDotIndexNew = keySession.fileName.lastIndexOf(".");
                            if (lastDotIndexNew != -1) {
                                keySession.fileExtension = keySession.fileName.substring(lastDotIndexNew);
                                keySession.fileNameWithoutExtension = keySession.fileName.substring(0,
                                        lastDotIndexNew);
                            }
                        } else if (!Files.exists(keySession.filePath)) {
                            try {
                                Files.createFile(keySession.filePath);
                                keySession.progressState = Progress.READING_FILEDATA;
                            } catch (Exception e) {
                                System.err.println("Failed to create file: " + keySession.filePath.toAbsolutePath());
                            }
                            break;
                        }
                    }
                }
            }

        }

        if (keySession.progressState == Progress.READING_FILEDATA) {
            if (keySession.chunkStatus == ChunkProgress.DEFAULT
                    || keySession.chunkStatus == ChunkProgress.CHUNK_WRITTEN_TO_FILE) {
                bytesRead = clientChannel.read(keySession.encChunkLengthBuffer);
                if (bytesRead < 0) {
                    cancelKey(key);
                    return;
                } else if (bytesRead > 0 && keySession.encChunkLengthBuffer
                        .position() < keySession.encChunkLengthBuffer.capacity()) {
                    return;
                } else if (bytesRead > 0 && keySession.encChunkLengthBuffer
                        .position() == keySession.encChunkLengthBuffer.capacity()) {
                    try {
                        byte[] decChunkLengthBytes = keySession.rsaDecrypt(keySession.encChunkLengthBuffer.array());
                        keySession.chunkLengthBuffer.clear().put(decChunkLengthBytes).flip();
                        keySession.lengthOfEncryptedChunk = keySession.chunkLengthBuffer.getInt();
                        keySession.chunkStatus = ChunkProgress.RECEIVING_CHUNK;
                        keySession.encChunkLengthBuffer.clear();
                    } catch (Exception e) {
                        System.err.println("An error occured while decrypting the chunk length for client "
                                + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                }
            }
            if (keySession.chunkStatus == ChunkProgress.RECEIVING_CHUNK) {
                bytesRead = clientChannel.read(keySession.encryptedFileChunkBuffer);
                if (bytesRead < 0) {
                    cancelKey(key);
                    return;
                } else if (bytesRead == 0) {
                    return; // continue reading
                } else if (bytesRead > 0
                        && keySession.encryptedFileChunkBuffer.position() < keySession.lengthOfEncryptedChunk) {
                    return; // continue reading
                } else if (bytesRead > 0
                        && keySession.encryptedFileChunkBuffer.position() == keySession.lengthOfEncryptedChunk) {
                    try {
                        keySession.encryptedFileChunkBuffer.flip();
                        byte[] validEncryptedBytes = new byte[keySession.encryptedFileChunkBuffer.remaining()];
                        keySession.encryptedFileChunkBuffer.get(validEncryptedBytes);
                        byte[] decFileChunkBytes = keySession.decrypt(validEncryptedBytes);
                        keySession.directFileChunkBuffer.clear().put(decFileChunkBytes).flip();
                        keySession.chunkStatus = ChunkProgress.WRITING_CHUNK_TO_FILE;
                        keySession.encryptedFileChunkBuffer.clear();
                    } catch (Exception e) {
                        System.err.println("An error occured while decrypting the file chunk for client "
                                + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                }
            }
            if (keySession.chunkStatus == ChunkProgress.WRITING_CHUNK_TO_FILE) {
                if (keySession.asyncFileChannel == null || !keySession.asyncFileChannel.isOpen()) {
                    try {
                        keySession.asyncFileChannel = AsynchronousFileChannel.open(keySession.filePath,
                                StandardOpenOption.WRITE);
                    } catch (Exception e) {
                        System.err.println(
                                "Failed to open async file channel: " + keySession.filePath.toAbsolutePath());
                        System.out.println("error message: " + e.getMessage());
                        return;
                    }
                }
                int prevOps = key.interestOps();
                key.interestOps(0);
                keySession.asyncFileChannel.write(keySession.directFileChunkBuffer, keySession.fileChannelPosition, key,
                        new CompletionHandler<Integer, SelectionKey>() {
                            @Override
                            public void completed(Integer result, SelectionKey attachment) {
                                keySession.fileChannelPosition += result; // updates the position for the next write
                                attachment.interestOps(prevOps);
                                attachment.selector().wakeup();
                                CurrentSession keySession = (CurrentSession) attachment.attachment();
                                SocketChannel clientChannel = (SocketChannel) attachment.channel();
                                try {
                                    if (keySession.asyncFileChannel.size() == keySession.fileSize) {
                                        keySession.chunkStatus = ChunkProgress.ALL_CHUNK_WRITTEN_TO_FILE;
                                        keySession.asyncFileChannel.close();
                                        System.out.println(
                                                "Received file from client " + clientChannel.getRemoteAddress() + ": "
                                                        + keySession.fileName);
                                        resetCurrentSessionObj(keySession);
                                        return;
                                    } else if (keySession.asyncFileChannel.size() < keySession.fileSize) {
                                        keySession.chunkStatus = ChunkProgress.CHUNK_WRITTEN_TO_FILE;
                                        return;
                                    }
                                } catch (Exception e) {
                                    try {
                                        System.err.println(
                                                "An error occured on the asynchronous file channel on file "
                                                        + keySession.fileName + " for client "
                                                        + clientChannel.getRemoteAddress());
                                    } catch (Exception ex) {
                                    }
                                }
                            }

                            @Override
                            public void failed(Throwable exc, SelectionKey attachment) {
                                attachment.interestOps(prevOps);
                                System.err.println(
                                        "An error occured while writing file chunk to file: " + exc.getMessage());
                            }
                        });
            }

        }

    }

    private static void cancelKey(SelectionKey key) {
        try {
            CurrentSession keySession = (CurrentSession) key.attachment();
            if (keySession != null) {
                cleanUpCurrentSessionObj(keySession);
            }
            key.attach(null);
            key.channel().close();
            key.cancel();
        } catch (Exception e) {
            System.err.println("An error occured while trying to cancel key " + e.getMessage());
        }
    }

    private static void serverShutdown() {
        try {
            if (selector != null && selector.isOpen()) {
                for (SelectionKey key : selector.keys()) {
                    cancelKey(key);
                }
                selector.close();
            }
            if (serverChannel != null && serverChannel.isOpen())
                serverChannel.close();
        } catch (Exception e) {
            // ignore shutdown errors
        }
    }

    private static void printConnectionGuide() {
        String bestIP = null;
        try {
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets)) {
                if (netint.isLoopback() || !netint.isUp() || netint.isVirtual())
                    continue;

                String name = netint.getDisplayName().toLowerCase();
                if (name.contains("virtual") || name.contains("vmware") || name.contains("docker")
                        || name.contains("vbox") || name.contains("vm"))
                    continue;

                Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
                for (InetAddress inetAddr : Collections.list(inetAddresses)) {
                    if (inetAddr instanceof Inet4Address) {
                        bestIP = inetAddr.getHostAddress();
                        ServerIPAdress = bestIP;
                        break;
                    }
                }
                if (bestIP != null)
                    break;
            }
        } catch (Exception e) {
            // Fallback to null logic handled below
        }

        System.out.println("\n-------------------------------------------");
        System.out.println("SERVER INITIALIZED ON PORT: " + PORT);

        if (bestIP != null) {
            System.out.println("STATUS: Network Active");
            System.out.println("-> Connect from other PCs on the same network via: " + bestIP);
            System.out.println("-> Connect from THIS PC via:    localhost");
        } else {
            System.out.println("STATUS: Offline / No Network Found");
            System.out.println("-> Only programs on THIS computer can connect.");
            System.out.println("-> Use: localhost (127.0.0.1)");
        }
        System.out.println("-------------------------------------------\n");
    }

    private static void cleanUpCurrentSessionObj(CurrentSession keySession) {
        keySession.progressState = null;
        keySession.chunkStatus = null;
        keySession.encHandShakeSendBuffer = null;
        keySession.handShakeReceiveBuffer = null;
        keySession.encHandShakeReceiveBuffer = null;
        keySession.decryptedHandShake = null;
        keySession.informationDetailsBuffer = null;
        keySession.encInformationDetailsBuffer = null;
        keySession.informationBuffer = null;
        keySession.decInformationStringBuffer = null;
        keySession.encInformationBuffer = null;
        keySession.decInformationBuffer = null;
        keySession.fileNameBuffer = null;
        keySession.encFileNameBuffer = null;
        keySession.decFileNameBuffer = null;
        keySession.serverECPublicKeyBuffer = null;
        keySession.commandReceiveBuffer = null;
        keySession.commandSendBuffer = null;
        keySession.encCommandReceiveBuffer = null;
        keySession.encCommandSendBuffer = null;
        keySession.fileNameLengthBuffer = null;
        keySession.encHandShakeSendLengthBuffer = null;
        keySession.handShakeReceiveLengthBuffer = null;
        keySession.encHandShakeReceiveLengthBuffer = null;
        keySession.encFileListLengthBuffer = null;
        keySession.encFileNameLengthBuffer = null;
        keySession.decFileNameLengthBuffer = null;
        keySession.informationLengthBuffer = null;
        keySession.encInformationLengthBuffer = null;
        keySession.decInformationLengthBuffer = null;
        keySession.fileSizeBuffer = null;
        keySession.encFileSizeBuffer = null;
        keySession.decFileSizeBuffer = null;
        keySession.chunkLengthBuffer = null;
        keySession.encChunkLengthBuffer = null;
        keySession.encFileListInfoHeaderBuffer = null;
        keySession.fileListInfoHeaderBuffer = null;
        keySession.unEncFileDetails256 = null;
        keySession.encFileDetails256 = null;
        keySession.informationBufferArr = null;
        keySession.fileDetailsBufferArr = null;
        keySession.encChunkLengthAndDataArr = null;
        keySession.handshakeBufferArrs = null;
        keySession.fileChannel = null;
        keySession.fileListTempFile = null;
        keySession.command = NO_COMMAND;
        keySession.encryptedFileListStringLength = 0;
        keySession.fileNameLength = 0;
        keySession.encFileNameLength = 0;
        keySession.decFileNameLength = 0;
        keySession.lengthOfEncryptedChunk = 0;
        keySession.fileSize = 0;
        keySession.c2cTransferCurrentPosition = 0;
        keySession.fileChannelPosition = 0;
        keySession.information = null;
        keySession.fileName = null;
        keySession.fileNameWithoutExtension = null;
        keySession.fileExtension = null;

        keySession.fileToSend = null;
        keySession.filePath = null;

        // clear nonce used in handshake
        keySession.nonceArray = null;

        // reset buffers used in chunk transfer
        keySession.directFileChunkBuffer = null;
        keySession.unencryptedFileChunkBuffer = null;
        keySession.encryptedFileChunkBuffer = null;

        keySession.nonceArray = null;
        keySession.additionalData = null;
        keySession.additionalDataBytes = null;

        keySession.secretKey = null;
        keySession.decryptCipher = null;
        keySession.encryptCipher = null;
        keySession.rsaDecryptCipher = null;
        keySession.rsaEncryptCipher = null;

        keySession.serverIV = null;
        keySession.clientIV = null;

        if (keySession.fileChannel != null && keySession.fileChannel.isOpen()) {
            try {
                keySession.fileChannel.close();
            } catch (Exception e) {
                System.err.println("Could not close file channel: " + e.getMessage());
            }
            keySession.fileChannel = null;
        }
        if (keySession.asyncFileChannel != null && keySession.asyncFileChannel.isOpen()) {
            try {
                keySession.asyncFileChannel.close();
            } catch (Exception e) {
                System.err.println("Could not close file channel: " + e.getMessage());
            }
            keySession.asyncFileChannel = null;
        }
    }

    private static void resetCurrentSessionObj(CurrentSession keySession) {
        keySession.progressState = Progress.VALID_HANDSHAKE;
        keySession.chunkStatus = ChunkProgress.DEFAULT;
        keySession.encHandShakeSendBuffer = null;
        keySession.handShakeReceiveBuffer = null;
        keySession.encHandShakeReceiveBuffer = null;
        keySession.decryptedHandShake = null;
        keySession.informationDetailsBuffer = null;
        keySession.encInformationDetailsBuffer = null;
        keySession.informationBuffer = null;
        keySession.decInformationStringBuffer = null;
        keySession.encInformationBuffer = null;
        keySession.decInformationBuffer = null;
        keySession.fileNameBuffer = null;
        keySession.encFileNameBuffer = null;
        keySession.decFileNameBuffer = null;
        keySession.serverECPublicKeyBuffer = null;
        keySession.commandReceiveBuffer.clear();
        keySession.commandSendBuffer.clear();
        keySession.encCommandReceiveBuffer.clear();
        keySession.encCommandSendBuffer.clear();
        keySession.fileNameLengthBuffer.clear();
        keySession.encHandShakeSendLengthBuffer.clear();
        keySession.handShakeReceiveLengthBuffer.clear();
        keySession.encHandShakeReceiveLengthBuffer.clear();
        keySession.encFileListLengthBuffer.clear();
        keySession.encFileNameLengthBuffer.clear();
        keySession.decFileNameLengthBuffer.clear();
        keySession.informationLengthBuffer.clear();
        keySession.encInformationLengthBuffer.clear();
        keySession.decInformationLengthBuffer.clear();
        keySession.fileSizeBuffer.clear();
        keySession.encFileSizeBuffer.clear();
        keySession.decFileSizeBuffer.clear();
        keySession.chunkLengthBuffer.clear();
        keySession.encChunkLengthBuffer.clear();
        keySession.encFileListInfoHeaderBuffer.clear();
        keySession.fileListInfoHeaderBuffer = null;
        keySession.unEncFileDetails256 = null;
        keySession.encFileDetails256.clear();
        keySession.informationBufferArr = null;
        keySession.fileDetailsBufferArr = null;
        keySession.encChunkLengthAndDataArr = null;
        keySession.handshakeBufferArrs = null;
        keySession.fileListTempFile = null;
        keySession.command = NO_COMMAND;
        keySession.encryptedFileListStringLength = 0;
        keySession.fileNameLength = 0;
        keySession.encFileNameLength = 0;
        keySession.decFileNameLength = 0;
        keySession.lengthOfEncryptedChunk = 0;
        keySession.fileSize = 0;
        keySession.c2cTransferCurrentPosition = 0;
        keySession.fileChannelPosition = 0;
        keySession.information = "";
        keySession.fileName = "";
        keySession.fileNameWithoutExtension = "";
        keySession.fileExtension = "";

        keySession.fileToSend = null;
        keySession.filePath = null;

        if (keySession.fileChannel != null && keySession.fileChannel.isOpen()) {
            try {
                keySession.fileChannel.close();
            } catch (Exception e) {
                System.err.println("Could not close file channel: " + e.getMessage());
            }
        }
        if (keySession.asyncFileChannel != null && keySession.asyncFileChannel.isOpen()) {
            try {
                keySession.asyncFileChannel.close();
            } catch (Exception e) {
                System.err.println("Could not close file channel: " + e.getMessage());
            }
            keySession.asyncFileChannel = null;
        }

        // clear nonce used in handshake
        keySession.nonceArray = null;

        // reset buffers used in chunk transfer
        keySession.directFileChunkBuffer.clear();
        keySession.unencryptedFileChunkBuffer.clear();
    }

    private static class CurrentSession {
        Progress progressState = null;
        ChunkProgress chunkStatus = ChunkProgress.DEFAULT;
        ByteBuffer encHandShakeSendBuffer = null;
        ByteBuffer handShakeReceiveBuffer = null;
        ByteBuffer encHandShakeReceiveBuffer = null;
        ByteBuffer decryptedHandShake = null;
        ByteBuffer informationDetailsBuffer = null;
        ByteBuffer encInformationDetailsBuffer = null;
        ByteBuffer informationBuffer = null;
        ByteBuffer decInformationStringBuffer = null;
        ByteBuffer encInformationBuffer = null;
        ByteBuffer decInformationBuffer = null;
        ByteBuffer fileNameBuffer = null;
        ByteBuffer encFileNameBuffer = null;
        ByteBuffer decFileNameBuffer = null;
        ByteBuffer serverECPublicKeyBuffer = null;
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
        ByteBuffer[] informationBufferArr = null;
        ByteBuffer[] fileDetailsBufferArr = null;
        ByteBuffer[] encChunkLengthAndDataArr = null;
        ByteBuffer[] handshakeBufferArrs = null;
        FileChannel fileChannel = null;
        AsynchronousFileChannel asyncFileChannel = null;
        Path fileListTempFile = null;
        int command = NO_COMMAND;
        long encryptedFileListStringLength = 0;
        int fileNameLength = 0;
        int encFileNameLength = 0;
        int decFileNameLength = 0;
        int lengthOfEncryptedChunk = 0;
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

        // This is used to track time and kill connections that do not complete
        // handshake on time
        long connectTime = System.currentTimeMillis();

        // Encryption and Decryption
        private final int IV_SIZE = 12;
        private final int TAG_BIT_LENGTH = 128;
        private final int NONCE_SIZE = 16;
        private byte[] nonceArray = new byte[NONCE_SIZE];
        private String additionalData = "SECURE_FILE_SHARING_V1";
        private byte[] additionalDataBytes = additionalData.getBytes();
        private ECPublicKey clientPublicKey;
        private RSAPublicKey clientRSAPublicKey;
        private ECPublicKey serverECPublicKey;
        private ECPrivateKey serverECPrivateKey;
        private SecretKey secretKey;

        Cipher encryptCipher;
        Cipher decryptCipher;
        Cipher rsaEncryptCipher;
        Cipher rsaDecryptCipher;

        private CurrentSession() throws Exception {
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

        private void generateServerBaseIV() {
            new SecureRandom().nextBytes(serverIV);
        }

        private void setupClientBaseIV(byte[] receivedClientBaseIV) {
            System.arraycopy(receivedClientBaseIV, 0, clientIV, 0, IV_SIZE);
        }

        private void secretKeySetup() throws Exception {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(serverECPrivateKey);
            ka.doPhase(clientPublicKey, true);
            byte[] rawSecret = ka.generateSecret();

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(rawSecret);
            SecretKeySpec secretKeySpec = new SecretKeySpec(hash, "AES");
            secretKey = secretKeySpec;
        }

        private byte[] encrypt(byte[] dataToEncrypt) throws Exception {
            GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, serverIV);
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            encryptCipher.updateAAD(additionalDataBytes);
            byte[] cipherText = encryptCipher.doFinal(dataToEncrypt);

            serverIVModifierBuffer.putLong(0, serverIVCounter++);

            return cipherText;
        }

        private byte[] decrypt(byte[] encryptedData) throws Exception {
            GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, clientIV);
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            decryptCipher.updateAAD(additionalDataBytes);

            clientIVModifierBuffer.putLong(0, clientIVCounter++);

            return decryptCipher.doFinal(encryptedData);

        }

        private byte[] rsaEncrypt(byte[] dataToEncrypt) throws Exception {
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            rsaEncryptCipher.init(Cipher.ENCRYPT_MODE, clientRSAPublicKey, spec);
            return rsaEncryptCipher.doFinal(dataToEncrypt);
        }

        private byte[] rsaDecrypt(byte[] encryptedData) throws Exception {
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            rsaDecryptCipher.init(Cipher.DECRYPT_MODE, serverRSAPrivateKey, spec);
            return rsaDecryptCipher.doFinal(encryptedData);
        }
    }

}
