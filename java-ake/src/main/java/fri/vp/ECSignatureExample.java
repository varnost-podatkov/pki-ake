package fri.vp;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

public class ECSignatureExample {
    public static void main(String[] args) throws Exception {
        final byte[] document = "An example document".getBytes(StandardCharsets.UTF_8);
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        final ECGenParameterSpec kpgParams = new ECGenParameterSpec("secp256r1");
        kpg.initialize(kpgParams);

        final KeyPair key = kpg.generateKeyPair();

        final Signature signer = Signature.getInstance("SHA256WithECDSA");
        signer.initSign(key.getPrivate());
        signer.update(document);
        final byte[] signature = signer.sign();
        System.out.println("Signature: " + Agent.hex(signature));

        final Signature verifier = Signature.getInstance("SHA256WithECDSA");
        verifier.initVerify(key.getPublic());
        verifier.update(document);

        if (verifier.verify(signature))
            System.out.println("Valid signature.");
        else
            System.err.println("Invalid signature.");
    }
}
