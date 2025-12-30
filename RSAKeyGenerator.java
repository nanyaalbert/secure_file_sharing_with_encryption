import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class RSAKeyGenerator {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        System.out.println("--- PUBLIC KEY ---");
        System.out.println(Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));

        System.out.println("\n--- PRIVATE KEY ---");
        System.out.println(Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
    }
}