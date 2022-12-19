package com.aaasec.sigserv.cscommon.metadata.mdq;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class MdqMetadataTest {

  private static X509Certificate mdCert;

  private static String entityId1 = "http://adfs.hv.se/adfs/services/trust";
  private static String entityId2 = "https://idp.iapg.cas.cz/idp/shibboleth";
  private static String entityId3 = "https://kimlik.altinbas.edu.tr/simplesaml/saml2/idp/metadata.php";
  private static String entityId4 = "https://shibprodapp.loyola.edu/idp/shibboleth";

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    String certB64 = "MIIDDzCCAfegAwIBAgIJAMVVy2WtqhKFMA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNVBAMME21kLm5v\n"
      + "cmR1Lm5ldCBTaWduZXIwHhcNMTMwNjI0MDc1MzE3WhcNMTMwNzI0MDc1MzE3WjAeMRwwGgYDVQQD\n"
      + "DBNtZC5ub3JkdS5uZXQgU2lnbmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4uOR\n"
      + "++VCPho4kjLqemMcowPWw7miY8rVAvEZYU+7rqLAnKKaRXVJw/TuRN0l1c+inaqhrQhMY3pKUp45\n"
      + "4TxfFpBsuuIEqAn0+YmE2PvQ1YggN44V6siDdHTIfJVR58q1ASWpXUBfPciz5FQCwfjVgRmk6TsE\n"
      + "W31ufzHSl//6gt0h5pi+TIY+rvXRvbifAylF72sGqlhcmxZVrFBcI+mk2g5Zh1rTK9Yh8PhF7TOx\n"
      + "Ny7F3Ohlxx/Sf+IBvVq87g35z9m3sGh/QgUI+TNdJmpWlaQYroeSLgU4wkQ4H7RReBnvEtNOjDFp\n"
      + "m4yVQ30A+TrvNaQNtV2s4efz9qROretE3QIDAQABo1AwTjAdBgNVHQ4EFgQUnhRpLS3lCE4dRZbG\n"
      + "fgqk0zJcvKAwHwYDVR0jBBgwFoAUnhRpLS3lCE4dRZbGfgqk0zJcvKAwDAYDVR0TBAUwAwEB/zAN\n"
      + "BgkqhkiG9w0BAQUFAAOCAQEAnOBSAAPcdfHTGwk0Mhg1haKH1PBrrUrFltQV6dicTwzdehfUK98y\n"
      + "CCM8Ha+OrOSoPIZYhfjHgTO4Yx0QKQLxPgTAcgI8m2qxDR29rb2UxiJMdKEH9lY3kA8G7ADf3IBN\n"
      + "jkicx4d/2DEa9cDPlROR4ISunUCqcNtZIA5ms6Tjie1r7Joof3dNpJ+sX5pkbgzYtxP2jwNCqfRG\n"
      + "hW7G++cyZKqyMwVGC09OsjViPqfsQCmrJIISxV//ZwICwIEKmBC25FDUwLPZULJspSRWuU5mLFS8\n"
      + "JS5X7SwfHL+dezDz1ZygEfuRZCATJBkKR41XkmOqrJJM2rOfQHPsx3AFO4+8wA==";

    byte[] certBytes = Base64.decode(certB64);

    try (ByteArrayInputStream in = new ByteArrayInputStream(certBytes)) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      mdCert = (X509Certificate) cf.generateCertificate(in);
    }
    catch (Exception e) {
      e.printStackTrace();
    }

    int sdf = 0;
  }

  @Test
  public void mdqTest() throws Exception {

    MdqMetadata mdqm = new MdqMetadata("https://md.nordu.net/entities/", mdCert);

    boolean entityIdSupported = mdqm.isEntityIdSupported(entityId1);
    entityIdSupported = mdqm.isEntityIdSupported(entityId1);
    entityIdSupported = mdqm.isEntityIdSupported(entityId2);
    entityIdSupported = mdqm.isEntityIdSupported(entityId3);
    entityIdSupported = mdqm.isEntityIdSupported(entityId4);

    Assertions.assertEquals(2, mdqm.getCertificates(entityId2).size());
    Assertions.assertEquals(4, mdqm.getEntityDataMap().size());

  }
}