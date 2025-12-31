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
    private static String HANDSHAKE_STRING = "SecureFileSharingHandShake";
    private static long TEMPFILENUMBER = 0;
    private static Path serverDownloadPath = Paths.get(System.getProperty("user.home"),
            "SecureFileSharingServerWithEncryption");
    private static Path serverTempPath = Paths.get(System.getProperty("user.home"),
            "SecureFileSharingServerWithEncryptionTemp");
    private static String ServerIPAdress;

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
        WRITING_INFORMATION,
        WRITING_HANDSHAKE,
        WRITING_FILELIST,
        VALID_HANDSHAKE,
        FILE_LIST_SAVED_TO_DISK
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
            System.err.println("An error occured when loading the handshake keys: " + e.getMessage());
            return;
        }
        server();
    }

    private static void server() {
        System.out.println("Welcome to the server");
        if (Files.notExists(serverDownloadPath)) {
            try {
                Files.createDirectories(serverDownloadPath);
            } catch (IOException e) {
                System.err.println("An error occured when creating the download directory: " + e.getMessage());
                return;
            }
        }

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
                        currentClientSession.progressState = Progress.JUST_CONNECTED;
                        clientChannel.register(selector, SelectionKey.OP_READ, currentClientSession);
                        System.out.println("Client " + clientChannel.getRemoteAddress() + " just connected");
                    }

                    if (key.isReadable()) {
                        SocketChannel readyClient = (SocketChannel) key.channel();
                        CurrentSession keySession = (CurrentSession) key.attachment();

                        // resume here
                        // add logic to read the first 256 bytes from the key's channel.
                        // decrypt those bytes to get the command

                        switch (keySession.progressState) {
                            case Progress.JUST_CONNECTED, Progress.READY_TO_READ_HANDSHAKE,
                                    Progress.READING_HANDSHAKE -> {
                                // Kills any connection that does not complete handshake send in 16 seconds
                                long currentTime = System.currentTimeMillis();
                                if (currentTime - keySession.connectTime > 16000) {
                                    System.err.println("Client " + readyClient.getRemoteAddress()
                                            + " took too long to complete handshake. disconnecting...");
                                    cancelKey(key);
                                    return;
                                }
                                readHandShake(key);
                            }
                            case Progress.WRITING_HANDSHAKE -> {
                                writeHandShake(key);
                            }
                            case Progress.VALID_HANDSHAKE -> {
                                if (keySession.command == NO_COMMAND) {
                                    readyClient.read(keySession.commandReceiveBuffer);
                                }
                                if (keySession.command == NO_COMMAND
                                        && keySession.commandReceiveBuffer.position() == keySession.commandReceiveBuffer
                                                .capacity()) {
                                    keySession.command = keySession.commandReceiveBuffer.getInt();
                                } else
                                    continue;
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
             * remaining bytes: the client ecdh public key
             */
            if (keySession.encHandShakeReceiveLengthBuffer.position() != keySession.encHandShakeReceiveLengthBuffer
                    .capacity()) {
                int bytesRead;
                bytesRead = clientChannel.read(keySession.encHandShakeReceiveLengthBuffer);
                if (bytesRead < 0) {
                    System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                    cancelKey(key);
                } else if (bytesRead > 0 && keySession.encHandShakeReceiveLengthBuffer.remaining() == 0) {
                    keySession.encHandShakeReceiveLengthBuffer.flip();
                    byte[] decrypted = keySession.rsaDecrypt(keySession.encHandShakeReceiveLengthBuffer.array());
                    ByteBuffer decryptedBuffer = ByteBuffer.wrap(decrypted);
                    decryptedBuffer.get(keySession.handShakeReceiveLengthBuffer.clear().array());
                    decryptedBuffer.get(keySession.nonceArray);
                    byte[] ecdhBytes = new byte[decryptedBuffer.remaining()];
                    decryptedBuffer.get(ecdhBytes);

                    X509EncodedKeySpec clientECPublicKeySpec = new X509EncodedKeySpec(ecdhBytes);
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
                                + "try recoonecting...");
                        cancelKey(key);
                        return;
                    }

                    keySession.progressState = Progress.READING_HANDSHAKE;
                    keySession.encHandShakeReceiveBuffer = ByteBuffer
                            .allocate(keySession.handShakeReceiveLengthBuffer.getInt());
                }
            }

            if (keySession.progressState == Progress.READING_HANDSHAKE) {
                int bytesRead;
                encHandShakeLength = keySession.handShakeReceiveLengthBuffer.getInt();
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
                ByteBuffer decryptedHandShake;
                if (keySession.encHandShakeReceiveBuffer.position() != encHandShakeLength) {
                    bytesRead = clientChannel.read(keySession.encHandShakeReceiveBuffer);
                    if (bytesRead < 0) {
                        System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                        cancelKey(key);
                    } else if (bytesRead > 0 && keySession.encHandShakeReceiveBuffer.position() == encHandShakeLength) {
                        keySession.encHandShakeReceiveBuffer.flip();
                        try {
                            decryptedHandShake = ByteBuffer
                                    .wrap(keySession
                                            .decrypt(keySession.encHandShakeReceiveBuffer.array()));
                        } catch (Exception e) {
                            System.err.println(
                                    clientChannel.getRemoteAddress() + " is not a valid client. disconnecting...");
                            cancelKey(key);
                            return;
                        }

                        byte[] decryptedHandshakeStringLengthArray = new byte[4];
                        decryptedHandShake.get(decryptedHandshakeStringLengthArray);
                        int handShakeStringLength = ByteBuffer.wrap(decryptedHandshakeStringLengthArray).flip()
                                .getInt();

                        byte[] clientRSAPublicKeyLengthArr = new byte[4];
                        decryptedHandShake.get(clientRSAPublicKeyLengthArr);
                        int clientRSAPublicKeyLength = ByteBuffer.wrap(clientRSAPublicKeyLengthArr).flip()
                                .getInt();
                        byte[] handshakeStringArray = new byte[handShakeStringLength];
                        decryptedHandShake.get(handshakeStringArray);
                        String handShakeString = new String(handshakeStringArray, StandardCharsets.UTF_8);
                        if (!handShakeString.equals(HANDSHAKE_STRING)) {
                            cancelKey(key);
                            return;
                        }

                        byte[] clientRSAPublicKeyArray = new byte[clientRSAPublicKeyLength];
                        decryptedHandShake.get(clientRSAPublicKeyArray);
                        X509EncodedKeySpec clientRSAPublicKeySpec = new X509EncodedKeySpec(
                                clientRSAPublicKeyArray);
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        try {
                            keySession.clientRSAPublicKey = (RSAPublicKey) keyFactory
                                    .generatePublic(clientRSAPublicKeySpec);
                        } catch (Exception e) {
                            System.err.println(
                                    "Could not generate handshake public key for " + clientChannel.getRemoteAddress()
                                            + "try recoonecting...");
                            cancelKey(key);
                            return;
                        }

                        keySession.handShakeReceiveLengthBuffer.clear();
                        keySession.handShakeReceiveBuffer.clear();

                        // prepare the handshake that will be sent to the client
                        int bufferCapacity = keySession.NONCE_SIZE + keySession.serverECPublicKey.getEncoded().length;
                        ByteBuffer handShakeToEncrypt = ByteBuffer.allocate(bufferCapacity);
                        handShakeToEncrypt.put(keySession.nonceArray);
                        handShakeToEncrypt.put(keySession.serverECPublicKey.getEncoded());
                        handShakeToEncrypt.flip();
                        /*
                         * RSA to encrypt the length
                         * AES-GCM to encrypt the actual handshake sent
                         */
                        try {
                            keySession.encHandShakeSendBuffer = ByteBuffer
                                    .wrap(keySession.encrypt(handShakeToEncrypt.array()));
                            int encLength = keySession.encHandShakeSendBuffer.capacity();
                            ByteBuffer encLengthBuffer = ByteBuffer.allocate(4);
                            encLengthBuffer.putInt(encLength).flip();
                            keySession.encHandShakeSendLengthBuffer.clear()
                                    .put(keySession.rsaEncrypt(encLengthBuffer.array()));
                        } catch (Exception e) {
                            System.err.println("Could not encrypt handshake for " + clientChannel.getRemoteAddress()
                                    + "try recoonecting...");
                            cancelKey(key);
                            return;
                        }
                        keySession.progressState = Progress.WRITING_HANDSHAKE;

                    }
                }

            }
        } catch (Exception e) {
            System.err.println("An error occured with the client " + clientChannel.getRemoteAddress());
        }

    }

    private static void writeHandShake(SelectionKey key) throws IOException {
        long bytesWritten;
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
        int prevOps = key.interestOps();
        key.interestOps(0);
        try {
            ByteBuffer[] handshakeBufferArrs = { keySession.encHandShakeSendLengthBuffer,
                    keySession.encHandShakeSendBuffer };
            bytesWritten = clientChannel.write(handshakeBufferArrs);
            if (bytesWritten < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
            } else if (bytesWritten > 0 && !keySession.encHandShakeSendBuffer.hasRemaining()) {
                keySession.encHandShakeSendLengthBuffer.clear();
                keySession.encHandShakeSendBuffer.clear();
                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                key.interestOps(prevOps);
                keySession.progressState = Progress.VALID_HANDSHAKE;
            } else if (bytesWritten == 0) {
                key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
            }
        } catch (Exception e) {
            System.err.println("An error occured with the client " + clientChannel.getRemoteAddress());
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
                    String fileList;
                    if (files.filter(Files::isRegularFile).findAny().isPresent()) {
                        fileList = files.filter(Files::isRegularFile).map(Path::getFileName)
                                .map(Path::toString)
                                .collect(Collectors.joining("\n"));
                    } else
                        fileList = "No files available on server";
                    // resume work here.
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
                    System.err.println("An error occured while trying to get file list " + e.getMessage());
                }
            }
        } else if (keySession.progressState == Progress.FILE_LIST_SAVED_TO_DISK) {
            if (keySession.fileChannel == null || !keySession.fileChannel.isOpen())
                return;
            long bytesWritten;
            if (keySession.encFileListInfoHeaderBuffer == null) {
                keySession.commandSendBuffer.clear().putInt(FILE_LIST);
                try {
                    byte[] encCommand = keySession.rsaEncrypt(keySession.commandSendBuffer.array());
                    keySession.encCommandSendBuffer = ByteBuffer.wrap(encCommand);
                } catch (Exception e) {
                    System.err.println("An error occured while encrypting command for client " + clientChannel.getRemoteAddress());
                    cancelKey(key);
                    return;
                }
                keySession.encryptedFileListStringLength = keySession.fileChannel.size();
                ByteBuffer encListLengthBuffer = ByteBuffer.allocate(8);
                encListLengthBuffer.putLong(keySession.encryptedFileListStringLength).flip();
                try {
                    keySession.encryptedFileListLengthBuffer.clear().put(keySession.rsaEncrypt(encListLengthBuffer.array()))
                        .flip();
                } catch (Exception e) {
                    System.err.println("An error occured while encrypting file list length for client " + clientChannel.getRemoteAddress());
                    cancelKey(key);
                    return;
                }
                int capacity = keySession.encCommandReceiveBuffer.capacity()
                        + keySession.encryptedFileListLengthBuffer.capacity();
                keySession.encFileListInfoHeaderBuffer = ByteBuffer.allocate(capacity);
                keySession.encFileListInfoHeaderBuffer.put(keySession.encCommandReceiveBuffer);
                keySession.encFileListInfoHeaderBuffer.put(keySession.encryptedFileListLengthBuffer);
                keySession.encFileListInfoHeaderBuffer.flip();
            }

            bytesWritten = clientChannel.write(keySession.encFileListInfoHeaderBuffer);
            if (bytesWritten < 0) {
                System.err.println("Client " + clientChannel.getRemoteAddress() + " closed the connection");
                cancelKey(key);
            } else if (bytesWritten > 0 && !keySession.encryptedFileListLengthBuffer.hasRemaining()) {
                keySession.commandReceiveBuffer.clear();
                keySession.encryptedFileListLengthBuffer.clear();
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

    private static void serverSendFile2(SelectionKey key) throws IOException {
        int bytesRead;
        SocketChannel readyClient = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
    }

    private static void serverSendFile(SelectionKey key) throws IOException {
        int bytesRead;
        SocketChannel readyClient = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();
        if (keySession.fileNameLengthBuffer.position() < 4) {
            bytesRead = readyClient.read(keySession.fileNameLengthBuffer);
            if (bytesRead < 0) {
                cancelKey(key);
                return;
            }
            if (keySession.fileNameLengthBuffer.position() < 4)
                return;
        }
        if (keySession.fileNameLengthBuffer.position() == 4
                && keySession.fileNameLength == 0) {
            keySession.fileNameLength = keySession.fileNameLengthBuffer.getInt();
        }
        if (keySession.fileNameLength > 0) {
            keySession.fileNameBuffer = ByteBuffer.allocate(keySession.fileNameLength);
            bytesRead = readyClient.read(keySession.fileNameBuffer);
            if (bytesRead < 0) {
                cancelKey(key);
                return;
            }
            if (keySession.fileNameBuffer.position() < keySession.fileNameLength)
                return;
        }
        if (keySession.fileNameBuffer.position() == keySession.fileNameLength
                && keySession.fileName.isEmpty()) {
            keySession.fileNameBuffer.flip();
            keySession.fileName = new String(keySession.fileNameBuffer.array(),
                    StandardCharsets.UTF_8);
        }
        if (keySession.fileSize == 0) {
            Path filePath = serverDownloadPath.resolve(keySession.fileName);
            if (Files.notExists(filePath)) {
                long bytesWritten;
                if (keySession.information.isEmpty()) {
                    keySession.information = "file \" " + keySession.fileName
                            + "\" does not exist";
                    keySession.informationBuffer = ByteBuffer
                            .wrap(keySession.information.getBytes(StandardCharsets.UTF_8));
                    keySession.informationSizeBuffer.clear()
                            .putInt(keySession.informationBuffer.capacity()).flip();
                    keySession.informationBufferArr = new ByteBuffer[] {
                            keySession.informationSizeBuffer,
                            keySession.informationBuffer };
                } else if (!keySession.information.isEmpty()
                        && keySession.informationBufferArr != null) {
                    bytesWritten = readyClient.write(keySession.informationBufferArr);
                    if (bytesWritten < 0) {
                        cancelKey(key);
                        return;
                    } else if (bytesWritten > 0
                            && !keySession.informationBuffer.hasRemaining()) {
                        resetCurrentSessionObj(keySession);
                        key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                    } else if (bytesWritten == 0) {
                        key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                    }
                }
            } else if (Files.exists(filePath)) {
                if (keySession.fileChannel == null || !keySession.fileChannel.isOpen()) {
                    keySession.fileChannel = FileChannel.open(filePath, StandardOpenOption.READ);
                    keySession.fileSize = keySession.fileChannel.size();
                    keySession.commandReceiveBuffer.putInt(FILE_DOWNLOAD);
                    keySession.fileDetailsBufferArr = new ByteBuffer[] { keySession.commandReceiveBuffer.flip(),
                            keySession.fileNameLengthBuffer.flip(), keySession.fileNameBuffer.flip() };
                    keySession.progressState = Progress.WRITING_FILEDETAILS;
                    key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                }
                if (keySession.progressState == Progress.WRITING_FILEDETAILS) {
                    long bytesWritten = readyClient.write(keySession.fileDetailsBufferArr);
                    if (bytesWritten < 0) {
                        cancelKey(key);
                        return;
                    } else if (bytesWritten > 0 && !keySession.fileNameBuffer.hasRemaining()) {
                        keySession.progressState = Progress.WRITING_FILEDATA;
                        key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                    } else if (bytesWritten == 0) {
                        key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                    }
                }
                if (keySession.progressState == Progress.WRITING_FILEDATA) {
                    long bytesWritten;
                    bytesWritten = keySession.fileChannel.transferTo(keySession.c2cTransferCurrentPosition,
                            keySession.fileChannel.size(), readyClient);
                    if (bytesWritten < 0) {
                        System.err.println("Client " + readyClient.getRemoteAddress() + " closed the connection");
                        cancelKey(key);
                    } else if (bytesWritten > 0) {
                        keySession.c2cTransferCurrentPosition += bytesWritten;
                        if (keySession.c2cTransferCurrentPosition == keySession.fileChannel.size()) {
                            keySession.fileChannel.close();
                            resetCurrentSessionObj(keySession);
                            key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
                        }
                    } else if (bytesWritten == 0) {
                        key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
                    }
                }
            }
        }
    }

    private static void serverReceiveFile(SelectionKey key) throws IOException {
        int bytesRead;
        SocketChannel readyClient = (SocketChannel) key.channel();
        CurrentSession keySession = (CurrentSession) key.attachment();

        if (keySession.fileNameLengthBuffer.position() < 4) {
            bytesRead = readyClient.read(keySession.fileNameLengthBuffer);
            if (bytesRead < 0) {
                cancelKey(key);
                return;
            }
            if (keySession.fileNameLengthBuffer.position() < 4)
                return;
        }
        if (keySession.fileNameLengthBuffer.position() == 4
                && keySession.fileNameLength == 0) {
            keySession.fileNameLength = keySession.fileNameLengthBuffer.getInt();
        }
        if (keySession.fileSizeBuffer.position() < 8) {
            bytesRead = readyClient.read(keySession.fileSizeBuffer);
            if (bytesRead < 0) {
                cancelKey(key);
                return;
            }
            if (keySession.fileSizeBuffer.position() < 8)
                return;
        }
        if (keySession.fileNameLength > 0) {
            keySession.fileNameBuffer = ByteBuffer.allocate(keySession.fileNameLength);
            bytesRead = readyClient.read(keySession.fileNameBuffer);
            if (bytesRead < 0) {
                cancelKey(key);
                return;
            }
            if (keySession.fileNameBuffer.position() < keySession.fileNameLength)
                return;
        }
        if (keySession.fileNameBuffer.position() == keySession.fileNameLength
                && keySession.fileName.isEmpty()) {
            keySession.fileNameBuffer.flip();
            keySession.fileName = new String(keySession.fileNameBuffer.array(),
                    StandardCharsets.UTF_8);
        }
        if (keySession.fileSizeBuffer.position() == 8
                && keySession.fileSize == 0) {
            keySession.fileSize = keySession.fileSizeBuffer.getLong();
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
            }
            if (keySession.progressState == Progress.READING_FILEDATA) {
                if (!keySession.fileChannel.isOpen()) {
                    try {
                        keySession.fileChannel = FileChannel.open(filePath, StandardOpenOption.WRITE);
                    } catch (Exception e) {
                        System.err.println(
                                "An error occured while trying to open channel on " + filePath.toAbsolutePath());
                        return;
                    }
                }
                if (keySession.fileChannel.isOpen()) {
                    long bytesReadToFile;
                    bytesReadToFile = keySession.fileChannel.transferFrom(readyClient,
                            keySession.c2cTransferCurrentPosition, keySession.fileSize);
                    if (bytesReadToFile < 0) {
                        keySession.fileChannel.close();
                        cancelKey(key);
                        return;
                    }
                    if (bytesReadToFile > 0) {
                        keySession.c2cTransferCurrentPosition += bytesReadToFile;
                        if (keySession.c2cTransferCurrentPosition == keySession.fileSize) {
                            System.out.println("File transfer completed for " + keySession.fileName);
                            try {
                                keySession.fileChannel.close();
                            } catch (Exception e) {
                                System.err.println("Failed to close file channel for " + keySession.fileName);
                            }
                            resetCurrentSessionObj(keySession);
                        }
                    }
                    if (bytesReadToFile == 0) {
                        key.interestOps(key.interestOps() | SelectionKey.OP_READ);
                    }
                }
            }
        }

    }

    private static void cancelKey(SelectionKey key) {
        try {
            key.cancel();
            key.channel().close();
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

    private static void resetCurrentSessionObj(CurrentSession keySession) {
        keySession.progressState = Progress.VALID_HANDSHAKE;
        keySession.encHandShakeSendBuffer = null;
        keySession.handShakeReceiveBuffer = null;
        keySession.encHandShakeReceiveBuffer = null;
        keySession.informationBuffer = null;
        keySession.fileNameBuffer = null;
        keySession.commandReceiveBuffer.clear();
        keySession.commandSendBuffer.clear();
        keySession.encCommandReceiveBuffer.clear();
        keySession.encCommandSendBuffer.clear();
        keySession.fileNameLengthBuffer.clear();
        keySession.encHandShakeSendLengthBuffer.clear();
        keySession.handShakeReceiveLengthBuffer.clear();
        keySession.encHandShakeReceiveLengthBuffer.clear();
        keySession.encryptedFileListLengthBuffer.clear();
        keySession.informationSizeBuffer.clear();
        keySession.fileSizeBuffer.clear();
        keySession.fileListInfoHeaderBuffer = null;
        keySession.encFileListInfoHeaderBuffer.clear();
        keySession.informationBufferArr = null;
        keySession.fileDetailsBufferArr = null;
        keySession.fileChannel = null;
        keySession.fileListTempFile = null;
        keySession.command = NO_COMMAND;
        keySession.encryptedFileListStringLength = 0;
        keySession.fileNameLength = 0;
        keySession.fileSize = 0;
        keySession.c2cTransferCurrentPosition = 0;
        keySession.information = "";
        keySession.fileName = "";
        keySession.fileNameWithoutExtension = "";
        keySession.fileExtension = "";

        // clear nonce used in handshake
        keySession.nonceArray = null;
    }

    private static class CurrentSession {
        Progress progressState = null;
        ByteBuffer encHandShakeSendBuffer = null;
        ByteBuffer handShakeReceiveBuffer = null;
        ByteBuffer encHandShakeReceiveBuffer = null;
        ByteBuffer informationBuffer = null;
        ByteBuffer fileNameBuffer = null;
        ByteBuffer commandReceiveBuffer = ByteBuffer.allocate(4);
        ByteBuffer encCommandReceiveBuffer = ByteBuffer.allocate(256);
        ByteBuffer commandSendBuffer = ByteBuffer.allocate(4);
        ByteBuffer encCommandSendBuffer = ByteBuffer.allocate(256);
        ByteBuffer fileNameLengthBuffer = ByteBuffer.allocate(4);
        ByteBuffer encHandShakeSendLengthBuffer = ByteBuffer.allocate(256);
        ByteBuffer handShakeReceiveLengthBuffer = ByteBuffer.allocate(4);
        ByteBuffer encHandShakeReceiveLengthBuffer = ByteBuffer.allocate(256);
        ByteBuffer informationSizeBuffer = ByteBuffer.allocate(4);
        ByteBuffer encryptedFileListLengthBuffer = ByteBuffer.allocate(256);
        ByteBuffer fileSizeBuffer = ByteBuffer.allocate(8);
        ByteBuffer fileListInfoHeaderBuffer = null;
        ByteBuffer encFileListInfoHeaderBuffer = ByteBuffer.allocate(256);
        ByteBuffer[] informationBufferArr = null;
        ByteBuffer[] fileDetailsBufferArr = null;
        FileChannel fileChannel = null;
        Path fileListTempFile = null;
        int command = NO_COMMAND;
        long encryptedFileListStringLength = 0;
        int fileNameLength = 0;
        long fileSize = 0;
        long c2cTransferCurrentPosition = 0;
        String information = "";
        String fileName = "";
        String fileNameWithoutExtension = "";
        String fileExtension = "";

        // This is used to track time and kill connections that do not complete
        // handshake on time
        long connectTime = System.currentTimeMillis();

        // Encryption and Decryption
        private static final int IV_SIZE = 12;
        private static final int TAG_BIT_LENGTH = 128;
        private static final int NONCE_SIZE = 16;
        private byte[] nonceArray = new byte[NONCE_SIZE];
        private String additionalData = "SERVER: " + ServerIPAdress + " PORT: " + PORT;
        private byte[] additionalDataBytes = additionalData.getBytes();
        private ECPublicKey clientPublicKey;
        private RSAPublicKey clientRSAPublicKey;
        private ECPublicKey serverECPublicKey;
        private ECPrivateKey serverECPrivateKey;
        private SecretKey secretKey;

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
            byte[] iv = new byte[IV_SIZE];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            cipher.updateAAD(additionalDataBytes);
            byte[] cipherText = cipher.doFinal(dataToEncrypt);

            return ByteBuffer.allocate(iv.length + cipherText.length).put(iv).put(cipherText).array();
        }

        private byte[] decrypt(byte[] encryptedData) throws Exception {
            ByteBuffer buffer = ByteBuffer.wrap(encryptedData);
            byte[] iv = new byte[IV_SIZE];
            buffer.get(iv);
            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            cipher.updateAAD(additionalDataBytes);

            return cipher.doFinal(cipherText);

        }

        // Handshake encryption and decryption methods

        // Move this Method to Client class
        // private byte[] encryptHandShakeAndMetadata(byte[] dataToEncrypt) throws
        // Exception {
        // new SecureRandom(nonceArray);
        // byte[] handShakestringBytes =
        // HANDSHAKE_STRING.getBytes(StandardCharsets.UTF_8);
        // int handShakeStringLength = handShakestringBytes.length;
        // byte[] clientPublickeyBytes = clientPublicKey.getEncoded();
        // int bufferSize = nonceArray.length + 4 + handShakestringBytes.length +
        // clientPublickeyBytes.length;
        // ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
        // buffer.put(nonceArray).putInt(handShakeStringLength).put(handShakestringBytes).put(clientPublickeyBytes).flip();
        // The code above will not be in the method. it will be runn before calling the
        // method to encrypt the handshake

        // change the encryption below to aes
        // Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        // OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
        // MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        // rsaCipher.init(Cipher.ENCRYPT_MODE, serverRSAPublicKey, spec);
        // return rsaCipher.doFinal(buffer.array()); // Change the buffer array to the
        // dataToEncrypt parameter

        // }

        private byte[] rsaEncrypt(byte[] dataToEncrypt) throws Exception {
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            rsaCipher.init(Cipher.ENCRYPT_MODE, clientRSAPublicKey, spec);
            return rsaCipher.doFinal(dataToEncrypt);
        }

        private byte[] rsaDecrypt(byte[] encryptedData) throws Exception {
            Cipher rsacipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            rsacipher.init(Cipher.DECRYPT_MODE, serverRSAPrivateKey, spec);
            return rsacipher.doFinal(encryptedData);
        }
    }

}
