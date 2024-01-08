package fri.vp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.HexFormat;

import static fri.vp.CertUtils.*;

public class A1OneSidedSimpleAKE {
    public static void main(String[] args) throws Exception {

        final Environment env = new Environment();

        final Certificate certCA = certFromFile("../cert_ca.pem");

        env.add(new Agent("ana") {
            @Override
            public void task() throws Exception {
                final byte[] r = receive("bor");
                final X509Certificate bor = certFromBytes(receive("bor"));

                bor.checkValidity();
                bor.verify(certCA.getPublicKey());

                final SecretKey key = KeyGenerator.getInstance("AES").generateKey();

                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                rsa.init(Cipher.ENCRYPT_MODE, bor.getPublicKey());
                rsa.update(r);
                rsa.update(key.getEncoded());
                send("bor", rsa.doFinal());

                print("Key: %s", HexFormat.of().formatHex(key.getEncoded()));
            }
        });

        env.add(new Agent("bor") {
            @Override
            public void task() throws Exception {
                final Certificate certBor = certFromFile("../cert_bor.pem");
                final RSAPrivateKey skBor = loadPrivateKey("../sk_bor.pem");

                final byte[] r = new byte[32];
                SecureRandom.getInstanceStrong().nextBytes(r);

                send("ana", r);
                send("ana", certBor.getEncoded());

                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                rsa.init(Cipher.DECRYPT_MODE, skBor);
                final byte[] rKey = rsa.doFinal(receive("ana"));

                if (!MessageDigest.isEqual(Arrays.copyOfRange(rKey, 0, 32), r)) {
                    print("Invalid R");
                    System.exit(-1);
                }

                final SecretKeySpec key = new SecretKeySpec(
                        Arrays.copyOfRange(rKey, 32, rKey.length),
                        "AES");

                print("Key: %s", HexFormat.of().formatHex(key.getEncoded()));
            }
        });

        env.connect("ana", "bor");
        env.start();
    }
}
