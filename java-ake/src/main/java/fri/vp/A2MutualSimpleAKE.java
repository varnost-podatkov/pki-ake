package fri.vp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignedObject;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;

import static fri.vp.CertUtils.*;

public class A2MutualSimpleAKE {
    public static void main(String[] args) throws Exception {

        final Environment env = new Environment();

        final Certificate certCA = certFromFile("../cert_ca.pem");

        env.add(new Agent("ana") {
            @Override
            public void task() throws Exception {
                final X509Certificate cert = certFromFile("../cert_ana.pem");
                final RSAPrivateKey sk = loadPrivateKey("../sk_ana.pem");

                final byte[] r = receive("bor");
                final X509Certificate bor = certFromBytes(receive("bor"));
                bor.checkValidity();
                bor.verify(certCA.getPublicKey());

                final SecretKey key = KeyGenerator.getInstance("AES").generateKey();

                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                rsa.init(Cipher.ENCRYPT_MODE, bor.getPublicKey());
                rsa.update(key.getEncoded());
                rsa.update(cert.getSubjectX500Principal().getName().getBytes(StandardCharsets.UTF_8));
                final byte[] c = rsa.doFinal();
                send("bor", c);
                send("bor", cert.getEncoded());

                final Signature signer = Signature.getInstance("RSASSA-PSS");
                signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                signer.initSign(sk);
                signer.update(r);
                signer.update(c);
                signer.update(bor.getSubjectX500Principal().getName().getBytes(StandardCharsets.UTF_8));
                send("bor", signer.sign());

                print("Key: %s", HexFormat.of().formatHex(key.getEncoded()));
            }
        });

        env.add(new Agent("bor") {
            @Override
            public void task() throws Exception {
                final X509Certificate cert = certFromFile("../cert_bor.pem");
                final RSAPrivateKey sk = loadPrivateKey("../sk_bor.pem");

                final byte[] r = new byte[32];
                SecureRandom.getInstanceStrong().nextBytes(r);

                send("ana", r);
                send("ana", cert.getEncoded());

                final byte[] c = receive("ana");
                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                rsa.init(Cipher.DECRYPT_MODE, sk);
                final byte[] keyName = rsa.doFinal(c);

                final SecretKeySpec key = new SecretKeySpec(
                        Arrays.copyOfRange(keyName, 0, 32),
                        "AES");
                final String decryptedName = new String(
                        Arrays.copyOfRange(keyName, 32, keyName.length),
                        StandardCharsets.UTF_8);

                final X509Certificate ana = certFromBytes(receive("ana"));
                ana.checkValidity();
                ana.verify(certCA.getPublicKey());

                if (!MessageDigest.isEqual(
                        decryptedName.getBytes(StandardCharsets.UTF_8),
                        ana.getSubjectX500Principal().getName().getBytes(StandardCharsets.UTF_8))) {
                    print("Invalid name");
                    System.exit(-1);
                }

                final Signature verifier = Signature.getInstance("RSASSA-PSS");
                verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                verifier.initVerify(ana.getPublicKey());
                verifier.update(r);
                verifier.update(c);
                verifier.update(cert.getSubjectX500Principal().getName().getBytes(StandardCharsets.UTF_8));

                if (!verifier.verify(receive("ana"))) {
                    print("Invalid signature, aborting!");
                    System.exit(-1);
                }

                print("Key: %s", HexFormat.of().formatHex(key.getEncoded()));
            }
        });

        env.connect("ana", "bor");
        env.start();
    }
}
