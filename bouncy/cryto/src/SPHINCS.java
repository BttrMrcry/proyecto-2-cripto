
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.sphincsplus.*;
import java.security.SecureRandom;

public class SPHINCS {

    public static void main(String[] args) {
        try {
            String msg = "Hello";
            String method = "haraka_128f";
            if (args.length > 0) {
                msg = args[0];
            }
            if (args.length > 1) {
                method = args[1];
            }
            SecureRandom random = new SecureRandom();
            SPHINCSPlusKeyGenerationParameters keyGenParameters = new SPHINCSPlusKeyGenerationParameters(random, SPHINCSPlusParameters.haraka_128f);

            if (method.equals("haraka_128f_simple")) {
                keyGenParameters = new SPHINCSPlusKeyGenerationParameters(random, SPHINCSPlusParameters.haraka_128f_simple);
            }
           

            SPHINCSPlusKeyPairGenerator keyPairGen = new SPHINCSPlusKeyPairGenerator();
            keyPairGen.init(keyGenParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGen.generateKeyPair();

            SPHINCSPlusPublicKeyParameters pubKey = (SPHINCSPlusPublicKeyParameters) keyPair.getPublic();
            SPHINCSPlusPrivateKeyParameters privKey = (SPHINCSPlusPrivateKeyParameters) keyPair.getPrivate();

            // Signing
            SPHINCSPlusSigner signer = new SPHINCSPlusSigner();
            signer.init(true, privKey);
            byte[] signature = signer.generateSignature(msg.getBytes());

            // Verify signature
            SPHINCSPlusSigner verifier = new SPHINCSPlusSigner();
            verifier.init(false, pubKey);
            boolean rtn = verifier.verifySignature(msg.getBytes(), signature);

            System.out.println("Message:\t" + msg);
            System.out.println("Method:\t\t" + method);

            System.out.println("\nPublic key (length):\t" + pubKey.getEncoded().length + " bytes");
            System.out.println("Public key:\t" + Hex.toHexString(pubKey.getEncoded()));

            System.out.println("\nPrivate key (length):\t" + privKey.getEncoded().length + " bytes");
            System.out.println("Private key:\t" + Hex.toHexString(privKey.getEncoded()));

            System.out.println("\nSignature (length):\t" + signature.length + " bytes");
            System.out.println("Signature (first 50 bytes):\t" + Hex.toHexString(signature).substring(0, 100));

            System.out.println("\nVerified:\t" + rtn);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
