package fri.vp;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RSAPSSSignature {

    public static KeyPair gen() throws Exception {
        return KeyPairGenerator.getInstance("RSASSA-PSS").generateKeyPair();
    }

    public static byte[] sign(PrivateKey key, byte[] message) throws Exception {
        final Signature signer = Signature.getInstance("RSASSA-PSS");
        signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signer.initSign(key);
        signer.update(message);
        return signer.sign();
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signature) throws Exception {
        final Signature verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(signature);
    }

    public static void main(String[] args) throws Exception {
        final byte[] document = "We would like to sign this.".getBytes(StandardCharsets.UTF_8);

        final KeyPair key = gen();
        Files.write(Path.of("../rsa.pk"), key.getPublic().getEncoded());
        Files.write(Path.of("../rsa.sk"), key.getPrivate().getEncoded());

        final byte[] signature = sign(key.getPrivate(), document);
        System.out.println("Signature: " + Agent.hex(signature));
        Files.write(Path.of("../rsa.sig"), signature);
        Files.write(Path.of("../rsa.msg"), document);

        if (verify(key.getPublic(), document, signature)) {
            System.out.println("Valid signature.");
        } else {
            System.err.println("Invalid signature.");
        }
    }
}
