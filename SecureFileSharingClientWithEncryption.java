import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
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
    private static final int STATUS_CONTINUE = 7;
    private static final int STATUS_FINISH = 8;
    private static String HANDSHAKE_STRING = "SecureFileSharingHandShake";
    private static long TEMPFILENUMBER = 0;
    private static Path clientDownloadPath = Paths.get(System.getProperty("user.home"),
            "SecureFileSharingClientWithEncryption");
    private static Path clientTempPath = Paths.get(System.getProperty("user.home"),
            "SecureFileSharingClientWithEncryptionTemp");
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

    private static RSAPublicKey clientRSAPublicKey;
    private static RSAPrivateKey clientRSAPrivateKey;
    private static ECPublicKey clientECPublicKey;
    private static ECPrivateKey clientECPrivateKey;
    private static final String SERVER_RSA_PUBLIC_KEY_STRING = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+TEpsZJxq1bDlcGsy4a//RRq3MMfYeE+1J6yL9LiqCf0hbdBE4y86sQjbUquoYi6VpTITiw7uzMg3wzRmkqABFtcbOtzNEeHSpqgMv88YRDlPbVutsE4JAxmm6BkA2cLqIgjM6jbZRrnR5kwaw/jWFmhOpazNRH/c6HWQ3KLFAUc/ZXBchm69gFOdtGJ939rzE9zzpLo5t+lp/kAbXbdug98Geo7Nky5A3rv3ooFAaRgwovCCKQWoKGFKndgk1TootJuLBH+DaeQ+sjDhlAByrygwuV9pPS31r1lYoWQ8Ls5RclfVIDxJLpmOxjx0x1Qn6ixnQ7P75Uy6rA9s3PiwIDAQAB";
    private static RSAPublicKey serverRSAPublicKey;
    private ECPublicKey serverPublicKey;

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
            System.out.println("An error occured when generating the client rsapublic and private key: " + e.getMessage());
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
            System.out.println("An error occured when generating the client ecdh public and private key: " + e.getMessage());
            return;
        }
        client();
    }

    private static void client(){}

    private static void readHandShake() throws IOException{}

    private static void writeHandShake() throws IOException{}

    private static void clientReceiveFileList() throws IOException{}

    private static void clientReceiveInformation() throws IOException{}

    private static void clientSendFile() throws IOException{}

    private static void clientReceiveFile() throws IOException{}

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

        // Encryption and Decryption
        private static final int IV_SIZE = 12;
        private static final int TAG_BIT_LENGTH = 128;
        private static final int NONCE_SIZE = 16;
        private byte[] nonceArray = new byte[NONCE_SIZE];
        private String additionalData = "SERVER: " + ServerIPAdress + " PORT: " + PORT;
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

        private void generateClientBaseIV() {
            new SecureRandom().nextBytes(serverIV);
        }

        private void setupServerBaseIV(byte[] receivedServerBaseIV) {
            clientIV = Arrays.copyOf(receivedServerBaseIV, IV_SIZE);
        }

        private void secretKeySetup() throws Exception {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(clientECPrivateKey);
            ka.doPhase(clientECPublicKey, true);
            byte[] rawSecret = ka.generateSecret();

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(rawSecret);
            SecretKeySpec secretKeySpec = new SecretKeySpec(hash, "AES");
            secretKey = secretKeySpec;
        }

        private byte[] encrypt(byte[] dataToEncrypt) throws Exception {
            clientIVModifierBuffer.putLong(0, clientIVCounter++);

            GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, clientIV);
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            encryptCipher.updateAAD(additionalDataBytes);
            byte[] cipherText = encryptCipher.doFinal(dataToEncrypt);

            return cipherText;
        }

        private byte[] decrypt(byte[] encryptedData) throws Exception {
            serverIVModifierBuffer.putLong(0, serverIVCounter++);

            GCMParameterSpec spec = new GCMParameterSpec(TAG_BIT_LENGTH, serverIV);
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            decryptCipher.updateAAD(additionalDataBytes);

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
