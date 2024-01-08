package fri.vp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class CertUtils {

    static {
        // Knjižnico BoucyCAstle moramo "ročno" vklopiti kot ponudnika varnostnih storitev
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate certFromFile(String file) throws Exception {
        return certFromBytes(Files.readAllBytes(Path.of(file)));
    }

    public static X509Certificate certFromBytes(byte[] bytes) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(bytes));
    }

    public static RSAPrivateKey loadPrivateKey(String file) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(file);
             final PemReader pemReader = new PemReader(keyReader)) {
            final PemObject pemObject = pemReader.readPemObject();
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
            return (RSAPrivateKey) factory.generatePrivate(keySpec);
        }
    }

    public static void main(String[] args) throws Exception {
        final Certificate certCA = certFromFile("../cert_ca.pem");
        final Certificate certAna = certFromFile("../cert_ana.pem");
        final Certificate certBor = certFromFile("../cert_bor.pem");
        final Certificate certCene = certFromFile("../cert_cene.pem");
//        final RSAPrivateKey skAna = loadPrivateKey("../sk_ana.pem");

        // hhttps://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/cert/X509Certificate.html
        certAna.verify(certCA.getPublicKey());
        System.out.println("Valid!");
        certBor.verify(certCA.getPublicKey());
        System.out.println("Valid!");
        certCene.verify(certAna.getPublicKey());
        System.out.println("Valid!");
    }
}
