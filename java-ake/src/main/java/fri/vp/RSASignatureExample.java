package fri.vp;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;

import static fri.vp.CertUtils.*;

public class RSASignatureExample {

    public static void main(String[] args) throws Exception {
        final Certificate cert = certFromFile("../cert_ana.pem");
        final RSAPrivateKey skAna = privateKeyFromFile("../sk_ana.pem");

        final String algorithm = "SHA256WithRSA";
        final String message = "A test message.";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

        System.out.println("Message: " + message);
        System.out.println("PT: " + Agent.hex(pt));

        final Signature signer = Signature.getInstance(algorithm);
        signer.initSign(skAna);
        signer.update(pt);
        final byte[] signature = signer.sign();

        System.out.println("Signature: " + Agent.hex(signature));

        final Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(cert.getPublicKey());
        verifier.update(pt);

        if (verifier.verify(signature)) {
            System.out.println("Signature valid");
        } else {
            System.err.println("Signature invalid");
        }
    }
}
