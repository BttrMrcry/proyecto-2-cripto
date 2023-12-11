import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;
import java.security.SecureRandom;
import org.bouncycastle.pqc.crypto.crystals.dilithium.*;
import org.bouncycastle.*;

public class DILITHIUM {

    public static void main(String[] args) {
        try {
            AsymmetricCipherKeyPair keyPair1 = generate();
            AsymmetricCipherKeyPair keyPair2 = generate();

            byte[] message = "Important Message!".getBytes();
            byte[] signature = sign((DilithiumPrivateKeyParameters) keyPair1.getPrivate(), message);

            // Returns TRUE
            boolean check1 = verify((DilithiumPublicKeyParameters) keyPair1.getPublic(), message, signature);
            // Returns FALSE (as expected)
            boolean check2 = verify((DilithiumPublicKeyParameters) keyPair2.getPublic(), message, signature);

            System.out.println("Verification 1: " + check1);
            System.out.println("Verification 2: " + check2);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    public static AsymmetricCipherKeyPair generate() {
        DilithiumKeyPairGenerator generator = new DilithiumKeyPairGenerator();
        DilithiumKeyGenerationParameters keyGenParameters = new DilithiumKeyGenerationParameters(
                new SecureRandom(),4,3,2,2,2,4,4);// RhoSize, you may need to adjust this value based on your needs
              
 
        generator.init(keyGenParameters);
        return generator.generateKeyPair();
    }

    public static byte[] sign(DilithiumPrivateKeyParameters privateKey, byte[] message) {
        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true, privateKey);

        signer.update(message, 0, message.length);
        return signer.generateSignature(message);
    }

    public static boolean verify(DilithiumPublicKeyParameters publicKey, byte[] message, byte[] signature) {
        DilithiumSigner verifier = new DilithiumSigner();
        verifier.init(false, publicKey);

        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature, signature);
    }
}