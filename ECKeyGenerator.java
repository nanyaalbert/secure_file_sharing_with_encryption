import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECKeyGenerator {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecSpec);

        KeyPair kp = kpg.generateKeyPair();

        System.out.println("--- ECDH PUBLIC KEY ---");
        System.out.println(Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));

        System.out.println("\n--- ECDH PRIVATE KEY ---");
        System.out.println(Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
    }
}