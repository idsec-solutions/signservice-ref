package com.aaasec.sigserv.sigauthsp.utils;

import com.aaasec.lib.crypto.PEM;
import com.aaasec.lib.utils.Base64Coder;
import com.aaasec.lib.utils.FileOps;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.aaasec.sigserv.sigauthsp.models.KeyStoreBundle;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;

/**
 *
 * @author stefan
 */
public class ApCredential {

    public static final String keyStorePassProperty = "keyStorePass";
    public static final String keyStoreSourceTypeProperty = "keyStoreSourceType";
    public static final String keyStoreLocationProperty = "keyStoreLocation";
    public static final String entityIdProperty = "entityId";
    public static final String usageProperty = "usage";
    public static final String sourceTypeProperty = "sourceType";
    private static final Properties entityProp = new Properties();
    private KeyStore keyStore;
    private String entityId;
    private char[] password;
    private String alias;
    private Certificate certificate;
    private Credential credential;

    public ApCredential(KeyStoreBundle ksBundle) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.keyStore = ksBundle.getKeyStore();
        this.password = ksBundle.getPassword();
        this.alias = ksBundle.getAlias();
        this.certificate = keyStore.getCertificate(alias);
        credential = getCredentialsFromKeyStore();
    }

    public ApCredential(byte[] certBytes) throws CertificateException {
        ByteArrayInputStream bis = new ByteArrayInputStream(certBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        while (bis.available() > 0) {
            certificate = cf.generateCertificate(bis);
        }
        credential = getCredentialFromCert();

    }

    public ApCredential(String entityName) {
        try {
            getEntityDetails(entityName);
            setCredential();
        } catch (Exception ex) {
            Logger.getLogger(ApCredential.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void setCredential() {
        if (keyStore == null) {
            credential = getCredentialFromCert();
            return;
        }
        try {
            credential = getCredentialsFromKeyStore();
        } catch (Exception ex) {
            Logger.getLogger(ApCredential.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public String getEntityId() {
        return entityId;
    }

    public String getAlias() {
        return alias;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public Credential getCredential() {
        return credential;
    }

    private Credential getCredentialsFromKeyStore() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (keyStore == null) {
            return null;
        }
        BasicCredential credential = new BasicCredential();
        credential.setEntityId(entityId);
        credential.setPrivateKey((PrivateKey) keyStore.getKey(alias, password));
        credential.setPublicKey(certificate.getPublicKey());
        credential.setUsageType(UsageType.UNSPECIFIED);

        return credential;
    }

    private Credential getCredentialFromCert() {
        BasicCredential credential = new BasicCredential();
        credential.setEntityId(entityId);
        credential.setPublicKey(certificate.getPublicKey());
        credential.setUsageType(UsageType.SIGNING);
        return credential;
    }

    private void setCredentialUsageType(BasicCredential credential) {
        switch (entityProp.getProperty(usageProperty).toLowerCase()) {
            case "signing":
                credential.setUsageType(UsageType.SIGNING);
                break;
            case "encryption":
                credential.setUsageType(UsageType.ENCRYPTION);
                break;
            default:
                credential.setUsageType(UsageType.UNSPECIFIED);
        }
    }

    private void getEntityDetails(String entityName) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        InputStream is = ApCredential.class.getClassLoader().getResourceAsStream(entityName + ".properties");
        entityProp.load(is);
        entityId = entityProp.getProperty(entityIdProperty);
        switch (entityProp.getProperty(sourceTypeProperty).toLowerCase()) {
            case "jks":
                getKeyStoreDetails();
                break;
            case "certificate":
                getCertDetails();
        }
    }

    private void getKeyStoreDetails() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        keyStore = KeyStore.getInstance("JKS");
        InputStream kis = entityProp.getProperty(keyStoreSourceTypeProperty).equalsIgnoreCase("resource")
                ? ApCredential.class.getClassLoader().getResourceAsStream(entityProp.getProperty(keyStoreLocationProperty))
                : new FileInputStream(entityProp.getProperty(keyStoreLocationProperty));

        keyStore.load(kis, password);
        alias = keyStore.aliases().nextElement();
        certificate = keyStore.getCertificate(alias);
        password = entityProp.getProperty(keyStorePassProperty).toCharArray();

    }

    private void getCertDetails() throws FileNotFoundException, CertificateException {
        InputStream kis = entityProp.getProperty(keyStoreSourceTypeProperty).equalsIgnoreCase("resource")
                ? ApCredential.class.getClassLoader().getResourceAsStream(entityProp.getProperty(keyStoreLocationProperty))
                : new FileInputStream(entityProp.getProperty(keyStoreLocationProperty));

        String certStr = PEM.trimPemCert(new String(FileOps.readStream(kis), Charset.forName("UTF-8")));
        ByteArrayInputStream bis = new ByteArrayInputStream(Base64Coder.decodeLines(certStr));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        while (bis.available() > 0) {
            certificate = cf.generateCertificate(bis);
        }
    }
}
