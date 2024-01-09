package fri.vp;

import fri.isp.Agent;
import fri.isp.Environment;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import static fri.vp.CertUtils.certFromFile;
import static fri.vp.CertUtils.privateKeyFromFile;

public class A1OneSidedSimpleAKE {
    public static void main(String[] args) throws Exception {

        final Environment env = new Environment();

        // certifikat CA uporabite kot globalno spremenljivko
        final X509Certificate certCA = certFromFile("../cert_ca.pem");

        env.add(new Agent("ana") {
            @Override
            public void task() throws Exception {

            }
        });

        env.add(new Agent("bor") {
            @Override
            public void task() throws Exception {
                final X509Certificate certBor = certFromFile("../cert_bor.pem");
                final RSAPrivateKey skBor = privateKeyFromFile("../sk_bor.pem");


            }
        });

        env.connect("ana", "bor");
        env.start();
    }
}
