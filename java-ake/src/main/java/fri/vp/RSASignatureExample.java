package fri.vp;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import static fri.vp.CertUtils.*;

public class RSASignatureExample {

    public static void main(String[] args) throws Exception {
        final Certificate cert = certFromFile("../cert_ana.pem");
        final RSAPrivateKey skAna = privateKeyFromFile("../sk_ana.pem");

        final String algorithm = "RSASSA-PSS";
        final String message = "A test message.";
        final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

        System.out.println("Message: " + message);
        System.out.println("PT: " + Agent.hex(pt));

        final Signature signer = Signature.getInstance(algorithm);
        signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signer.initSign(skAna);
        signer.update(pt);
        final byte[] signature = signer.sign();

        System.out.println("Signature: " + Agent.hex(signature));

        final Signature verifier = Signature.getInstance(algorithm);
        verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        verifier.initVerify(cert.getPublicKey());
        verifier.update(pt);

        if (verifier.verify(signature)) {
            System.out.println("Signature valid");
        } else {
            System.err.println("Signature invalid");
        }
    }
}
