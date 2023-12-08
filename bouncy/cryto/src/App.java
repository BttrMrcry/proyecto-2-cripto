import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.Arrays;
import java.security.SecureRandom;


public class App {
    public static void main(String[] args) throws Exception {
        String temp = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
        byte[] seed = Hex.decode(temp);
        SecureRandom random = new SecureRandom(seed);
        KyberKeyPairGenerator keyGen = new KyberKeyPairGenerator();
        keyGen.init(new KyberKeyGenerationParameters(random, KyberParameters.kyber768));
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();
        KyberKEMGenerator kemGen = new KyberKEMGenerator(random);
        SecretWithEncapsulation secretEncap = kemGen.generateEncapsulated(keyPair.getPublic());
        KyberKEMExtractor kemExtract = new KyberKEMExtractor((KyberPrivateKeyParameters)keyPair.getPrivate());
        byte[] decryptedSharedSecret = kemExtract.extractSecret(secretEncap.getEncapsulation());
        System.out.println(decryptedSharedSecret);
        System.out.println(secretEncap.getSecret());
        if(Arrays.areEqual(decryptedSharedSecret, secretEncap.getSecret())){
            System.out.println("Los secretos se generaron correctamente");
        }else{
            System.out.println("Ocurrió un error");
        }

    }
}
