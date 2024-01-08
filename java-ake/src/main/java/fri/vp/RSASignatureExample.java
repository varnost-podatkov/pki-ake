package fri.vp;

import fri.isp.Agent;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class RSASignatureExample {
    public static void main(String[] args) throws Exception {

        final String algorithm = "RSAwithSHA256";
        final String message = "A test message.";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

        System.out.println("Message: " + message);
        System.out.println("PT: " + Agent.hex(pt));

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair bobKP = kpg.generateKeyPair();

        final Signature signer = Signature.getInstance(algorithm);
        signer.initSign(bobKP.getPrivate());
        signer.update(pt);
        final byte[] ct = signer.sign();

        System.out.println("CT: " + Agent.hex(ct));

        // STEP 4: Bob decrypts the cipher text using the same algorithm and his private key.
        final Cipher rsaDec = Cipher.getInstance(algorithm);
        rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
        final byte[] decryptedText = rsaDec.doFinal(ct);

        // STEP 5: Bob displays the clear text
        System.out.println("PT: " + Agent.hex(decryptedText));
        final String message2 = new String(decryptedText, StandardCharsets.UTF_8);
        System.out.println("Message: " + message2);
    }
}
