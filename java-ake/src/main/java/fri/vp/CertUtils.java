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
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class CertUtils {

    static {
        // Knjižnico BoucyCastle moramo "ročno" vklopiti kot ponudnika varnostnih storitev
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate certFromFile(String file) throws Exception {
        return certFromBytes(Files.readAllBytes(Path.of(file)));
    }

    public static X509Certificate certFromBytes(byte[] bytes) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(bytes));
    }

    public static RSAPrivateKey privateKeyFromFile(String file) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (FileReader keyReader = new FileReader(file);
             final PemReader pemReader = new PemReader(keyReader)) {
            final PemObject pemObject = pemReader.readPemObject();
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
            return (RSAPrivateKey) factory.generatePrivate(keySpec);
        }
    }

    public static void main(String[] args) throws Exception {
        // Preberemo certifikat CA in ga izpišemo
        final X509Certificate certCA = certFromFile("../cert_ca.pem");
        System.out.println(certCA);

        // Preberemo še Anin certifikat
        final X509Certificate certAna = certFromFile("../cert_ana.pem");
        // In še njen zasebni ključ zasebni ključ
        final RSAPrivateKey skAna = privateKeyFromFile("../sk_ana.pem");
        System.out.println(certAna);
        System.out.println(skAna);


        // Dokumentacija vmesnika API za delo s certifikati X509 v Javi
        // https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/cert/X509Certificate.html

        // Preverimo, ali je Anin certifikat res izdala certifikatna agencija
        certAna.verify(certCA.getPublicKey());

        // Če ni, bi se sprožila izjema: npr. Cenetov certifikat je podpisala Ana (in ne CA),
        // zato se pri preverjanju sproži izjema
        final X509Certificate certCene = certFromFile("../cert_cene.pem");
        try {
            certCene.verify(certCA.getPublicKey());
        } catch (SignatureException e) {
            System.out.println("Napaka pri preverjanju Cenetovega certifikata: " + e.getMessage());
        }

        // Če pa preverimo z Aninim certifikatom, pa preverjanje uspe
        certCene.verify(certAna.getPublicKey());
        System.out.println("Res je Ana podpisala Cenetov certifikat.");
    }
}
