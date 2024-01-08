package fri.vp;

import fri.isp.Agent;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class Ed25519Signature {

    public static KeyPair gen() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    public static byte[] sign(PrivateKey key, byte[] message) throws Exception {
        final Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(message);
        return signer.sign();
    }

    public static boolean verify(PublicKey key, byte[] message, byte[] signature) throws Exception {
        final Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(signature);
    }

    public static void main(String[] args) throws Exception {
        final byte[] document = "We would like to sign this.".getBytes(StandardCharsets.UTF_8);

        final KeyPair key = gen();
        Files.write(Path.of("../ed25519.pk"), key.getPublic().getEncoded());
        Files.write(Path.of("../ed25519.sk"), key.getPrivate().getEncoded());

        final byte[] signature = sign(key.getPrivate(), document);
        System.out.println("Signature: " + Agent.hex(signature));
        Files.write(Path.of("../ed25519.sig"), signature);
        Files.write(Path.of("../ed25519.msg"), document);

        if (verify(key.getPublic(), document, signature)) {
            System.out.println("Valid signature.");
        } else {
            System.err.println("Invalid signature.");
        }
    }
}
