import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
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
    private static final int NO_COMMAND = 0;
    private static final int FILE_SEND_REQUEST = 1;
    private static final int FILE_UPLOAD_REQUEST = 2;
    private static final int FILE_DOWNLOAD = 3;
    private static final int FILE_LIST_REQUEST = 4;
    private static final int FILE_LIST = 5;
    private static final int INFORMATION = 6;
    private static String HANDSHAKE_STRING = "SecureFileSharingHandShake";
    private static long TEMPFILENUMBER = 0;
    private static Path serverDownloadPath = Paths.get(System.getProperty("user.home"),
            "SecureFileSharingServerWithEncryption");
    private static Path serverTempPath = Paths.get(System.getProperty("java.io.tmpdir"),
            "SecureFileSharingServerWithEncryptionTemp");
    private static String ServerIPAdress;

    private enum Progress {
        JUST_CONNECTED,
        READING_FILEDATA,
        READING_FILEDETAILS,
        READING_INFORMATION,
        READING_HANDSHAKE,
        READING_FILELIST,
        WRITING_FILEDATA,
        WRITING_FILEDETAILS,
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

    private static final String RSA_PUBLIC_KEY_STRING = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+TEpsZJxq1bDlcGsy4a//RRq3MMfYeE+1J6yL9LiqCf0hbdBE4y86sQjbUquoYi6VpTITiw7uzMg3wzRmkqABFtcbOtzNEeHSpqgMv88YRDlPbVutsE4JAxmm6BkA2cLqIgjM6jbZRrnR5kwaw/jWFmhOpazNRH/c6HWQ3KLFAUc/ZXBchm69gFOdtGJ939rzE9zzpLo5t+lp/kAbXbdug98Geo7Nky5A3rv3ooFAaRgwovCCKQWoKGFKndgk1TootJuLBH+DaeQ+sjDhlAByrygwuV9pPS31r1lYoWQ8Ls5RclfVIDxJLpmOxjx0x1Qn6ixnQ7P75Uy6rA9s3PiwIDAQAB";
    private static final String RSA_PRIVATE_KEY_STRING = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC35MSmxknGrVsOVwazLhr/9FGrcwx9h4T7UnrIv0uKoJ/SFt0ETjLzqxCNtSq6hiLpWlMhOLDu7MyDfDNGaSoAEW1xs63M0R4dKmqAy/zxhEOU9tW62wTgkDGaboGQDZwuoiCMzqNtlGudHmTBrD+NYWaE6lrM1Ef9zodZDcosUBRz9lcFyGbr2AU520Yn3f2vMT3POkujm36Wn+QBtdt26D3wZ6js2TLkDeu/eigUBpGDCi8IIpBagoYUqd2CTVOii0m4sEf4Np5D6yMOGUAHKvKDC5X2k9LfWvWVihZDwuzlFyV9UgPEkumY7GPHTHVCfqLGdDs/vlTLqsD2zc+LAgMBAAECggEAHb2CzFIPRnFs44HRlJLlTPXPa4H8yCRtrlOlhefiKLZXgput/O9EsEG/OJvPIEFnTgQMo7fObaWgYbdpd360izRGVfgwKIq9awwcE15qNwkkAOh2onSfck3/p7EthQWed7BCwWL97U/uo4dx1hysXoodEWvxaWT/i52mKBHh246FiyEzzH9cpTPKtx7CgyDwq8kdORF7XD2a8DDMrUBBnc8JeTY9glOysnOx2y0GYAq2JMOIfTM/7JtNvBAnIGvnNhW6BDA01Bw2ubpeklBHzq69Jrv4AbjAGNyLcB47//75KYaASxseCnk0sEqcFfSe7oFZBVgI9ojR2H9LAXFsmQKBgQDIqioRfivmbg/Cg2QH4dGzqbG5KbJfwlzyBoLQeWqdNmmIHBA4cs2GS6q8Dv4ABgPgM5g5TNM2+64MqhctkIgmW7yCEAfFMVX82v3TWQvXNVv8pe3dgiBrXyfcD98xtNCymJckraUS7cThAZQ38DvWsQ0CR1gLoJlffTPVOIM0xwKBgQDqmqgwO9zqRNGDZa+aAqAcmIxRs/tQrY6pNq43WbQ3Xd+njIRMc1mj5X/M5+U1rO/Gstftvk+vKohiJdwbxlFe+/VZpJhaGF6Rwo6r+u5kz58XvUFN8lffvrFRNBX8P0PvK5ZZaix9ip6d6yYd3ap0OXiYMfzNtwNT6DJKF5mDHQKBgHT1shWGHCJwbmEq4kgx2F/G/h717dEg4bn0D5Vh38GIsJQz/0RXrfGj8v0wI95xoxqwF/72B3pZ0gXxshbN0n3BJKwOmejXK854+k+Q7HTg1h/5ux5MNYc/7GS5H5fCU451oEsxpzDUQ9f+apz8OnSVuAZm/SuxzRO6T1btXJSLAoGAdjaN7xgK/iTFKZ+Qd1tBUIdxlS3KweFiVFOQP6W80HVF4EhG1br9/T8EQbzL21sTyxyM/2f5APu+ky4elgQ9Nk5hV9U/S46iAHJ3r6MWgse3k5+yi1NFAiI1eQR025EJazecX9vHJU83E73MjBoI7N2UraPqjcHdNGd5B6qSmOUCgYEAozffWpGd0aCBAb2CJriEmGTwm4Yr+Yp0/yqWv9RFYP1PnFvKDY1vpaktankZTNeVwY2J0Cc1GNiUGnPn9V+nbLK/kPdqZ6Q8aTvln9vRYkRYl6KUdQetARiI8/mPXUK8Io8+eieHjVIN/SELQC+Lu66sUwjoQi3lu5Z3Zg6ECE4=";
    private static RSAPublicKey serverRSAPublicKey;
    private static RSAPrivateKey serverRSAPrivateKey;

    public static void main(String[] args) {
        try {
            byte[] rsaPublicKeyBytes = Base64.getDecoder().decode(RSA_PUBLIC_KEY_STRING);
            byte[] rsaPrivateKeyBytes = Base64.getDecoder().decode(RSA_PRIVATE_KEY_STRING);
            serverRSAPublicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(rsaPublicKeyBytes));
            serverRSAPrivateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(rsaPrivateKeyBytes));
        } catch (Exception e) {
            System.err.println("An error occured when loading the server rsa keys: " + e.getMessage());
            return;
        }

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

        try (ServerSocketChannel serverChannel = ServerSocketChannel.open(); Selector selector = Selector.open()) {
            serverChannel.configureBlocking(false);
            InetSocketAddress serverAddress = new InetSocketAddress("0.0.0.0", PORT);
            serverChannel.bind(serverAddress);
            printConnectionGuide();
            Scanner userInput = new Scanner(System.in);
            System.out.println("Please setup a password for the server.");
            System.out.println("Enter password: ");
            HANDSHAKE_STRING += userInput.nextLine();
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
                        clientChannel.register(selector, SelectionKey.OP_READ, currentClientSession);
                        System.out.println("Client " + clientChannel.getRemoteAddress() + " just connected");
                    }

                    if (key.isReadable()) {
                        SocketChannel readyClient = (SocketChannel) key.channel();
                        CurrentSession keySession = (CurrentSession) key.attachment();

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
                                if (keySession.command == NO_COMMAND) {
                                    // do nothing
                                    continue;
                                }
                                if (keySession.command != NO_COMMAND || keySession.command != FILE_SEND_REQUEST
                                        || keySession.command != FILE_UPLOAD_REQUEST
                                        || keySession.command != FILE_LIST_REQUEST) {
                                    // Invalid command, cancel this key and move to the next
                                    System.err.println("Invalid command; client " + readyClient.getRemoteAddress()
                                            + " may have closed the connection...");
                                    cancelKey(key);
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
                            }
                            case Progress.WRITING_FILEDETAILS, Progress.WRITING_FILEDATA -> {
                                serverSendFile(key);
                            }
                            case Progress.READING_FILEDATA -> {
                                serverReceiveFile(key);
                            }
                            case Progress.FILE_LIST_SAVED_TO_DISK, Progress.WRITING_FILELIST -> {
                                serverSendFilesList(key);
                            }

                        }

                    }
                }
            }

        } catch (Exception e) {
            System.out.println("An error occured with the server: " + e.getMessage());
        }

    }

    private static void readHandShake(SelectionKey key) throws IOException {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
        int encHandShakeLength;
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
                            byte[] exactBytes = new byte[keySession.encHandShakeReceiveBuffer.remaining()];
                            keySession.encHandShakeReceiveBuffer.get(exactBytes);
                            keySession.decryptedHandShake = ByteBuffer.wrap(keySession.decrypt(exactBytes));
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
                        byte[] handshakeStringArray = new byte[handShakeStringLength];
                        keySession.decryptedHandShake.get(handshakeStringArray);
                        String handShakeString = new String(handshakeStringArray, StandardCharsets.UTF_8);
                        if (!handShakeString.equals(HANDSHAKE_STRING)) {
                            System.err.println("Client " + clientChannel.getRemoteAddress()
                                    + " handshake string does not match. disconnecting...");
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

    private static void writeHandShake(SelectionKey key) throws IOException {
        long bytesWritten;
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
        if (keySession.progressState == Progress.WRITING_HANDSHAKE_SERVER_EC_PUBLIC_KEY) {
            try {
                // the server already received the client's EC public Key in encrypted form
                // so it's safe to send the server's EC public key in unencrypted form
                // send the length of the key and then the actual key
                if (keySession.serverECPublicKeyBuffer == null) {
                    byte[] serverECBase64 = Base64.getEncoder().encode(keySession.serverECPublicKey.getEncoded());
                    int ECLength = serverECBase64.length;
                    keySession.serverECPublicKeyBuffer = ByteBuffer.allocate(4 + ECLength);
                    keySession.serverECPublicKeyBuffer.putInt(ECLength);
                    keySession.serverECPublicKeyBuffer.put(serverECBase64);
                    keySession.serverECPublicKeyBuffer.flip();
                }
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                bytesWritten = clientChannel.write(keySession.serverECPublicKeyBuffer);
                if (bytesWritten < 0) {
                    System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                    cancelKey(key);
                } else if (bytesWritten > 0 && !keySession.serverECPublicKeyBuffer.hasRemaining()) {
                    keySession.serverECPublicKeyBuffer.clear();
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
    private static void serverSendFilesList(SelectionKey key) throws IOException {
        CurrentSession keySession = (CurrentSession) key.attachment();
        SocketChannel clientChannel = (SocketChannel) key.channel();
        if (keySession.fileChannel == null || !keySession.fileChannel.isOpen()) {
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
                                    attachment.interestOps(prevOps);
                                    CurrentSession keySession = (CurrentSession) attachment.attachment();
                                    try {
                                        keySession.fileChannel = FileChannel.open(keySession.fileListTempFile,
                                                StandardOpenOption.READ);
                                        keySession.progressState = Progress.FILE_LIST_SAVED_TO_DISK;
                                    } catch (Exception e) {
                                        System.out.println("An error occured while opening file channel on File: "
                                                + keySession.fileListTempFile.getFileName().toString());
                                    }
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
        } else if (keySession.progressState == Progress.FILE_LIST_SAVED_TO_DISK) {
            if (keySession.fileChannel == null || !keySession.fileChannel.isOpen())
                return;
            long bytesWritten;

            if(keySession.encFileListInfoHeaderBuffer == null){
                keySession.fileListInfoHeaderBuffer = ByteBuffer.allocate(4 + 8);
                keySession.fileListInfoHeaderBuffer.putInt(FILE_LIST);
                keySession.fileListInfoHeaderBuffer.putLong(keySession.fileChannel.size());
                keySession.fileListInfoHeaderBuffer.flip();
                try {
                    keySession.encFileListInfoHeaderBuffer = ByteBuffer.wrap(keySession.rsaEncrypt(keySession.fileListInfoHeaderBuffer.array()));
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
            } else if (bytesWritten > 0 && !keySession.encFileListInfoHeaderBuffer.hasRemaining()) {
                keySession.progressState = Progress.WRITING_FILELIST;
                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
            } else if (bytesWritten == 0) {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
            }

        } else if (keySession.progressState == Progress.WRITING_FILELIST) {
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
                    keySession.fileChannel.close();
                    key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                    Files.deleteIfExists(keySession.fileListTempFile);
                    resetCurrentSessionObj(keySession);
                }
            } else if (bytesWritten == 0) {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
            }
        } else {
            try {
                keySession.fileChannel = FileChannel.open(keySession.fileListTempFile, StandardOpenOption.READ);
                keySession.progressState = Progress.FILE_LIST_SAVED_TO_DISK;
            } catch (Exception e) {
                System.out.println("An error occured while sending file list to client ");
            }
        }
    }

    private static void serverSendFile(SelectionKey key) throws IOException {
        int bytesRead;
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
        if (keySession.encFileNameLengthBuffer.position() < keySession.encFileNameLengthBuffer.capacity()) {
            bytesRead = clientChannel.read(keySession.encFileNameLengthBuffer);
            if (bytesRead < 0) {
                cancelKey(key);
                return;
            }
            if (keySession.encFileNameLengthBuffer.position() < keySession.encFileNameLengthBuffer
                    .capacity())
                return;
            keySession.encFileNameLengthBuffer.flip();
            try {
                byte[] decFNLBytes = new byte[keySession.decFileNameLengthBuffer.capacity()];
                decFNLBytes = keySession.decrypt(keySession.encFileNameLengthBuffer.array());
                keySession.decFileNameLengthBuffer.put(decFNLBytes);
            } catch (Exception e) {
                System.err.println("An error occured while decrypting file name length for client "
                        + clientChannel.getRemoteAddress());
                cancelKey(key);
                return;
            }
        }
        if (keySession.decFileNameLengthBuffer.position() == keySession.decFileNameLengthBuffer
                .capacity()) {
            keySession.decFileNameLengthBuffer.flip();
            keySession.decFileNameLength = keySession.decFileNameLengthBuffer.getInt();
        }
        if (keySession.decFileNameLength <= 0) {
            System.err.println("Invalid file name length for client " + clientChannel.getRemoteAddress());
            cancelKey(key);
            return;
        } else {
            keySession.encFileNameBuffer = ByteBuffer.allocate(keySession.decFileNameLength);
            bytesRead = clientChannel.read(keySession.encFileNameBuffer);
            if (bytesRead < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
                return;
            }
            if (keySession.encFileNameBuffer.position() < keySession.decFileNameLength)
                return;
            keySession.encFileNameBuffer.flip();
            try {
                byte[] decFNBytes = keySession.decrypt(keySession.encFileNameBuffer.array());
                keySession.decFileNameBuffer = ByteBuffer.wrap(decFNBytes);
                keySession.decFileNameBuffer.flip();
                keySession.fileName = new String(keySession.decFileNameBuffer.array(), StandardCharsets.UTF_8);
            } catch (Exception e) {
                System.err.println("An error occured while decrypting file name for client "
                        + clientChannel.getRemoteAddress());
                cancelKey(key);
                return;
            }
            if (keySession.fileName.isEmpty()) {
                System.err.println("Invalid file name for client " + clientChannel.getRemoteAddress());
                cancelKey(key);
                return;
            }
        }
        if (keySession.fileSize == 0 || keySession.progressState == Progress.WRITING_FILEDETAILS
                || keySession.progressState == Progress.WRITING_FILEDATA) {
            Path filePath = serverDownloadPath.resolve(keySession.fileName);
            if (Files.notExists(filePath)) {
                int bytesWritten;
                if (keySession.progressState != Progress.WRITING_INFORMATION) {
                    keySession.information = "file \" " + keySession.fileName
                            + "\" does not exist";
                    try {
                        byte[] encInfoBytes = keySession
                                .encrypt(keySession.information.getBytes(StandardCharsets.UTF_8));
                        keySession.encInformationStringBuffer = ByteBuffer.wrap(encInfoBytes);
                        keySession.informationLengthBuffer.putInt(keySession.encInformationStringBuffer.capacity());
                        keySession.informationLengthBuffer.flip();
                        byte[] encInfoLengthBytes = keySession.rsaEncrypt(keySession.informationLengthBuffer.array());
                        keySession.encInformationLengthBuffer.put(encInfoLengthBytes);
                        keySession.encInformationLengthBuffer.flip();

                        try {
                            keySession.commandSendBuffer.clear().putInt(INFORMATION).flip();
                            byte[] encCommand = keySession.rsaEncrypt(keySession.commandSendBuffer.array());
                            keySession.encCommandSendBuffer = ByteBuffer.wrap(encCommand);
                        } catch (Exception e) {
                            System.err.println(
                                    "An error occured while encrypting command for client "
                                            + clientChannel.getRemoteAddress());
                            cancelKey(key);
                            return;
                        }
                        int capacity = keySession.encCommandSendBuffer.capacity()
                                + keySession.encInformationLengthBuffer.capacity()
                                + keySession.encInformationStringBuffer.capacity();

                        keySession.encInformationBuffer = ByteBuffer.allocate(capacity);
                        /*
                         * encrypted command at the first 256 bytes
                         * encrypted information length at the next 256 bytes
                         * encrypted information at the remaining bytes
                         */
                        keySession.encInformationBuffer.put(keySession.encCommandSendBuffer);
                        keySession.encInformationBuffer.put(keySession.encInformationLengthBuffer);
                        keySession.encInformationBuffer.put(keySession.encInformationStringBuffer);
                        keySession.encInformationBuffer.flip();

                        keySession.progressState = Progress.WRITING_INFORMATION;
                    } catch (Exception e) {
                        System.err.println("An error occured while encrypting information for client "
                                + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                } else if (keySession.progressState == Progress.WRITING_INFORMATION) {
                    bytesWritten = clientChannel.write(keySession.encInformationBuffer);
                    if (bytesWritten < 0) {
                        System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                        cancelKey(key);
                        return;
                    } else if (bytesWritten > 0 && !keySession.encInformationBuffer.hasRemaining()) {
                        key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                        resetCurrentSessionObj(keySession);
                    } else if (bytesWritten == 0) {
                        key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                    }
                }

            } else if (Files.exists(filePath)) {
                if (keySession.commandSendBuffer.getInt() != FILE_DOWNLOAD) {
                    try {
                        keySession.commandSendBuffer.clear().putInt(FILE_DOWNLOAD).flip();
                        byte[] encCommand = keySession.rsaEncrypt(keySession.commandSendBuffer.array());
                        keySession.encCommandSendBuffer = ByteBuffer.wrap(encCommand);
                    } catch (Exception e) {
                        System.err.println(
                                "An error occured while encrypting command for client "
                                        + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                }
                if (keySession.fileSize <= 0) {
                    keySession.fileSize = Files.size(filePath);
                    keySession.fileSizeBuffer.putLong(keySession.fileSize);
                    keySession.fileSizeBuffer.flip();
                    byte[] encFileSizeBytes;
                    try {
                        encFileSizeBytes = keySession.rsaEncrypt(keySession.fileSizeBuffer.array());
                    } catch (Exception e) {
                        System.err.println("An error occured while encrypting file size for client "
                                + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                    keySession.encFileSizeBuffer = ByteBuffer.wrap(encFileSizeBytes);
                    keySession.encFileSizeBuffer.flip();
                }
                if (keySession.encFileNameLength <= 0) {
                    keySession.fileName = filePath.getFileName().toString();
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
                    keySession.encFileNameBuffer.flip();
                    ByteBuffer lengthOfEncFileNameBytesBuffer = ByteBuffer.allocate(4);
                    lengthOfEncFileNameBytesBuffer.putInt(keySession.encFileNameBuffer.capacity());
                    lengthOfEncFileNameBytesBuffer.flip();
                    byte[] encLengthOfEncFileNameBytes;
                    try {
                        encLengthOfEncFileNameBytes = keySession.rsaEncrypt(lengthOfEncFileNameBytesBuffer.array());
                    } catch (Exception e) {
                        System.err.println("An error occured while encrypting length of encrypted file name for client "
                                + clientChannel.getRemoteAddress());
                        cancelKey(key);
                        return;
                    }
                    keySession.encFileNameLengthBuffer.put(encLengthOfEncFileNameBytes).flip();
                    keySession.encFileNameLength = keySession.encFileNameLengthBuffer.getInt();
                    keySession.encFileNameLengthBuffer.flip(); // flipped again because of the getInt() call

                    /*
                     * encrypted command at the first 256 bytes
                     * encrypted file size at the next 256 bytes
                     * encrypted filename length at the next 256 bytes
                     * encrypted filename at the remaining bytes
                     */
                    keySession.fileDetailsBufferArr = new ByteBuffer[] { keySession.encCommandSendBuffer,
                            keySession.encFileSizeBuffer, keySession.encFileNameLengthBuffer,
                            keySession.encFileNameBuffer };
                    keySession.progressState = Progress.WRITING_FILEDETAILS;
                }
                if (keySession.progressState == Progress.WRITING_FILEDETAILS) {
                    long bytesWritten;
                    bytesWritten = clientChannel.write(keySession.fileDetailsBufferArr);
                    if (bytesWritten < 0) {
                        System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                        cancelKey(key);
                        return;
                    } else if (bytesWritten > 0 && !keySession.encFileNameBuffer.hasRemaining()) {
                        key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                        keySession.progressState = Progress.WRITING_FILEDATA;

                    } else if (bytesWritten == 0) {
                        key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                    }
                }
                if (keySession.progressState == Progress.WRITING_FILEDATA) {
                    if (!keySession.fileChannel.isOpen()) {
                        try {
                            keySession.fileChannel = FileChannel.open(filePath, StandardOpenOption.READ);
                            keySession.fileSize = keySession.fileChannel.size();
                        } catch (Exception e) {
                            System.err.println("An error occured while opening fileChannel on the file : "
                                    + keySession.fileName + " for client " + clientChannel.getRemoteAddress());
                            return; // exit the method and try again
                        }
                    }
                    if (keySession.fileChannel.isOpen()) {
                        long bytesReadFromFile;
                        long bytesWritten;

                        if (keySession.fileChannelPosition < keySession.fileSize) {
                            if (keySession.chunkStatus == ChunkProgress.DEFAULT
                                    || keySession.chunkStatus == ChunkProgress.CHUNK_SENT) {
                                bytesReadFromFile = keySession.fileChannel.read(
                                        keySession.unencryptedFileChunkBuffer.clear(), keySession.fileChannelPosition);
                                if (bytesReadFromFile < 0) {
                                    return; // exit the method and try again
                                }
                                keySession.unencryptedFileChunkBuffer.flip();
                                keySession.fileChannelPosition += bytesReadFromFile;

                                byte[] encFileChunkBytes;
                                try {
                                    encFileChunkBytes = keySession
                                            .encrypt(keySession.unencryptedFileChunkBuffer.array());
                                } catch (Exception e) {
                                    System.err.println("An error occured while encrypting the file chunk for client "
                                            + clientChannel.getRemoteAddress());
                                    cancelKey(key);
                                    return;
                                }
                                keySession.directFileChunkBuffer.put(encFileChunkBytes).flip();
                                keySession.chunkLengthBuffer.putInt(keySession.directFileChunkBuffer.remaining())
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
                                keySession.encChunkLengthBuffer.put(encLengthBytes).flip();

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
                                }
                                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                            } else if (bytesWritten == 0) {
                                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                            }
                        }
                        if (keySession.chunkStatus == ChunkProgress.ALL_CHUNK_SENT) {
                            resetCurrentSessionObj(keySession);
                            return;
                        }

                    }
                }

            }

        }
    }

    private static void serverReceiveFile(SelectionKey key) throws IOException {
        int bytesRead;
        long bytesWrittenToFile;
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();

        if (keySession.fileSize <= 0) {
            bytesRead = clientChannel.read(keySession.encFileSizeBuffer);
            if (bytesRead < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
                return;
            } else if (bytesRead > 0
                    && keySession.encFileSizeBuffer.position() == keySession.encFileSizeBuffer.capacity()) {
                try {
                    byte[] decFileSizeBytes = keySession.rsaDecrypt(keySession.encFileSizeBuffer.array());
                    keySession.fileSizeBuffer.put(decFileSizeBytes).flip();
                    keySession.fileSize = keySession.fileSizeBuffer.getLong();
                } catch (Exception e) {
                    System.err.println("An error occured while decrypting the file size for client "
                            + clientChannel.getRemoteAddress());
                    cancelKey(key);
                    return;
                }
            }

        }
        if (keySession.fileNameLength <= 0 && keySession.fileSize > 0) {
            bytesRead = clientChannel.read(keySession.encFileNameLengthBuffer);
            if (bytesRead < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
                return;
            } else if (bytesRead > 0
                    && keySession.encFileNameLengthBuffer.position() == keySession.encFileNameLengthBuffer.capacity()) {
                try {
                    byte[] decFileNameLengthBytes = keySession.rsaDecrypt(keySession.encFileNameLengthBuffer.array());
                    keySession.fileNameLengthBuffer.put(decFileNameLengthBytes).flip();
                    keySession.fileNameLength = keySession.fileNameLengthBuffer.getInt();
                } catch (Exception e) {
                    System.err.println("An error occured while decrypting the file name length for client "
                            + clientChannel.getRemoteAddress());
                    cancelKey(key);
                    return;
                }
            }
        }
        if (keySession.fileNameLength > 0 && keySession.fileName.isEmpty()) {
            bytesRead = clientChannel.read(keySession.encFileNameBuffer);
            if (bytesRead < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
                return;
            } else if (bytesRead > 0 && keySession.encFileNameBuffer.position() == keySession.fileNameLength) {
                try {
                    byte[] decFileNameBytes = keySession.decrypt(keySession.encFileNameBuffer.array());
                    keySession.fileNameBuffer.put(decFileNameBytes).flip();
                    keySession.fileName = new String(keySession.fileNameBuffer.array(), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    System.err.println("An error occured while decrypting the file name for client "
                            + clientChannel.getRemoteAddress());
                    cancelKey(key);
                    return;
                }
            }

        }
        if (!keySession.fileName.isEmpty() && keySession.fileSize != 0) {
            Path filePath = serverDownloadPath.resolve(keySession.fileName);
            int lastDotIndex = keySession.fileName.lastIndexOf(".");
            keySession.fileExtension = keySession.fileName.substring(lastDotIndex);
            keySession.fileNameWithoutExtension = keySession.fileName.substring(0, lastDotIndex);
            if (keySession.progressState != Progress.READING_FILEDATA) {
                int counter = 0;
                while (true) {
                    if (Files.exists(filePath)) {
                        counter++;
                        filePath = serverDownloadPath
                                .resolve(keySession.fileNameWithoutExtension + "(" + counter + ")"
                                        + keySession.fileExtension);
                        keySession.fileName = filePath.getFileName().toString();
                        int lastDotIndexNew = filePath.getFileName().toString().lastIndexOf(".");
                        keySession.fileExtension = filePath.getFileName().toString().substring(lastDotIndexNew);
                        keySession.fileNameWithoutExtension = filePath.getFileName().toString().substring(0,
                                lastDotIndexNew);
                    } else {
                        try {
                            Files.createFile(filePath);
                            keySession.progressState = Progress.READING_FILEDATA;
                        } catch (Exception e) {
                            System.err.println("Failed to create file: " + filePath.toAbsolutePath());
                        }
                        break;
                    }
                }
            } else if (keySession.progressState == Progress.READING_FILEDATA) {
                if (keySession.chunkStatus == ChunkProgress.DEFAULT
                        || keySession.chunkStatus == ChunkProgress.CHUNK_WRITTEN_TO_FILE) {
                    bytesRead = clientChannel.read(keySession.encChunkLengthBuffer);
                    if (bytesRead < 0) {
                        cancelKey(key);
                        return;
                    } else if (bytesRead > 0 && keySession.encChunkLengthBuffer
                            .position() == keySession.encChunkLengthBuffer.capacity()) {
                        try {
                            byte[] decChunkLengthBytes = keySession.rsaDecrypt(keySession.encChunkLengthBuffer.array());
                            keySession.chunkLengthBuffer.put(decChunkLengthBytes).flip();
                            keySession.lengthOfEncryptedChunk = keySession.chunkLengthBuffer.getInt();
                            keySession.chunkStatus = ChunkProgress.RECEIVING_CHUNK;
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
                    } else if (bytesRead > 0
                            && keySession.encryptedFileChunkBuffer.position() == keySession.lengthOfEncryptedChunk) {
                        try {
                            byte[] decFileChunkBytes = keySession.decrypt(keySession.encryptedFileChunkBuffer.array());
                            keySession.directFileChunkBuffer.put(decFileChunkBytes).flip();
                            keySession.chunkStatus = ChunkProgress.WRITING_CHUNK_TO_FILE;
                        } catch (Exception e) {
                            System.err.println("An error occured while decrypting the file chunk for client "
                                    + clientChannel.getRemoteAddress());
                            cancelKey(key);
                            return;
                        }
                    }
                }
                if (keySession.chunkStatus == ChunkProgress.WRITING_CHUNK_TO_FILE) {
                    AsynchronousFileChannel asyncFileChannel = AsynchronousFileChannel.open(filePath,
                            StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                    int prevOps = key.interestOps();
                    key.interestOps(0);
                    asyncFileChannel.write(keySession.directFileChunkBuffer, 0, key,
                            new CompletionHandler<Integer, SelectionKey>() {
                                @Override
                                public void completed(Integer result, SelectionKey attachment) {
                                    attachment.interestOps(prevOps);
                                    CurrentSession keySession = (CurrentSession) attachment.attachment();
                                    SocketChannel clientChannel = (SocketChannel) attachment.channel();
                                    try {
                                        if (asyncFileChannel.size() == keySession.fileSize) {
                                            keySession.chunkStatus = ChunkProgress.ALL_CHUNK_WRITTEN_TO_FILE;
                                            asyncFileChannel.close();
                                        } else if (asyncFileChannel.size() < keySession.fileSize) {
                                            keySession.chunkStatus = ChunkProgress.CHUNK_WRITTEN_TO_FILE;
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
                if (keySession.chunkStatus == ChunkProgress.ALL_CHUNK_WRITTEN_TO_FILE) {
                    resetCurrentSessionObj(keySession);
                }

            }
        }

    }

    private static void cancelKey(SelectionKey key) {
        try {
            CurrentSession keySession = (CurrentSession) key.attachment();
            cleanUpCurrentSessionObj(keySession);
            key.attach(null);
            key.channel().close();
            key.cancel();
        } catch (Exception e) {
            System.err.println("An error occured while trying to cancel key " + e.getMessage());
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
        keySession.informationBuffer = null;
        keySession.encInformationStringBuffer = null;
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
        keySession.fileListInfoHeaderBuffer = null;
        keySession.encFileListInfoHeaderBuffer = null;
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
    }

    private static void resetCurrentSessionObj(CurrentSession keySession) {
        keySession.progressState = Progress.VALID_HANDSHAKE;
        keySession.chunkStatus = ChunkProgress.DEFAULT;
        keySession.encHandShakeSendBuffer = null;
        keySession.handShakeReceiveBuffer = null;
        keySession.encHandShakeReceiveBuffer = null;
        keySession.decryptedHandShake = null;
        keySession.informationBuffer = null;
        keySession.encInformationStringBuffer = null;
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

        if (keySession.fileChannel != null && keySession.fileChannel.isOpen()) {
            try {
                keySession.fileChannel.close();
            } catch (Exception e) {
                System.err.println("Could not close file channel: " + e.getMessage());
            }
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
        ByteBuffer informationBuffer = null;
        ByteBuffer encInformationStringBuffer = null;
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
        ByteBuffer[] informationBufferArr = null;
        ByteBuffer[] fileDetailsBufferArr = null;
        ByteBuffer[] encChunkLengthAndDataArr = null;
        ByteBuffer[] handshakeBufferArrs = null;
        FileChannel fileChannel = null;
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
