package fri.vp;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class Ed25519SignatureExample {
    public static void main(String[] args) throws Exception {
        final byte[] document = "An example document".getBytes(StandardCharsets.UTF_8);
        final KeyPair key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        final Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key.getPrivate());
        signer.update(document);
        final byte[] signature = signer.sign();
        System.out.println("Signature: " + Agent.hex(signature));

        final Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key.getPublic());
        verifier.update(document);

        if (verifier.verify(signature))
            System.out.println("Valid signature.");
        else
            System.err.println("Invalid signature.");
    }
}
