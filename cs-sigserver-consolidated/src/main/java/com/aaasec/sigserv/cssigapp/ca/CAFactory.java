/*
 * Copyright 2013 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *   Licensed under the EUPL, Version 1.1 or ñ as soon they will be approved by the 
 *   European Commission - subsequent versions of the EUPL (the "Licence");
 *   You may not use this work except in compliance with the Licence. 
 *   You may obtain a copy of the Licence at:
 * 
 *   http://joinup.ec.europa.eu/software/page/eupl 
 * 
 *   Unless required by applicable law or agreed to in writing, software distributed 
 *   under the Licence is distributed on an "AS IS" basis,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
 *   implied.
 *   See the Licence for the specific language governing permissions and limitations 
 *   under the Licence.
 */
package com.aaasec.sigserv.cssigapp.ca;

import com.aaasec.sigserv.cscommon.FnvHash;
import com.aaasec.sigserv.cssigapp.data.DbCAParam;
import com.aaasec.sigserv.cssigapp.data.SigConfig;
import com.aaasec.sigserv.cssigapp.models.SigServerModel;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.PolicyInformation;
import iaik.x509.V3Extension;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.CertificatePolicies;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectKeyIdentifier;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class creates certification authorities.
 */
public class CAFactory implements CaKeyStoreConstants {

    private static final Logger LOG = Logger.getLogger(CAFactory.class.getName());
    private KeyStore key_store;
    private File keyStoreFile;
    protected KeyPair ca_rsa = null;
    private String caName;
    private String caID;
    private SigServerModel model;
    protected CertificationAuthority ca;
    private SigConfig conf;

    public CAFactory() {
    }

    /**
     * Initiates generation of a root CA
     * @param ca The name of the policy for which a CA is to be created
     */
    public void createCa(CertificationAuthority ca) {
        this.ca = ca;
        caName = ca.getCaName();
        model = ca.getModel();
        conf = model.getConf();
        caID = FnvHash.getFNV1aToHex(caName);
        keyStoreFile = ca.getKeyStoreFile();
        keyStoreFile.getParentFile().mkdirs();
        LOG.info("New keystore generated at: " + keyStoreFile.getAbsolutePath());

        if (!keyStoreFile.canRead()) {
            createKeyStore(keyStoreFile);
            DbCAParam cp = new DbCAParam();
            cp.setParamName(CERT_SERIAL_KEY);
            cp.setIntValue(2);
            ca.getParamDb().addOrReplaceRecord(cp);
            cp = new DbCAParam();
            cp.setParamName(CRL_SERIAL_KEY);
            cp.setIntValue(1);
            ca.getParamDb().addOrReplaceRecord(cp);
            ca.initKeyStore();
        } else {
            return;
        }
    }

    private void createKeyStore(File keyStoreFile) {
        try {
            // get a new KeyStore onject
//            key_store = KeyStore.getInstance("IAIKKeyStore", "IAIK");
            key_store = KeyStore.getInstance("JKS");
            key_store.load(null, null);
            generateRootCertificate();
            saveKeyStore(ca.getKsPassword());
        } catch (Exception ex) {
            LOG.log(Level.WARNING, null, ex);
        }

    }

    /**
     * Generate a KeyPair using the specified algorithm with the given size.
     *
     * @param algorithm the algorithm to use
     * @param bits the length of the key (modulus) in bits
     *
     * @return the KeyPair
     *
     * @exception NoSuchAlgorithmException if no KeyPairGenerator is available for
     *                                     the requested algorithm
     */
    protected static KeyPair generateKeyPair(String algorithm, int bits)
            throws NoSuchAlgorithmException {

        KeyPair kp = null;
        KeyPairGenerator generator = null;
//        try {
//            generator = KeyPairGenerator.getInstance(algorithm, "IAIK");
        generator = KeyPairGenerator.getInstance(algorithm);
//        } catch (NoSuchProviderException ex) {
//            throw new NoSuchAlgorithmException("Provider IAIK not found!");
//        }
        generator.initialize(bits);
        kp = generator.generateKeyPair();
        return kp;
    }

    protected void generateRootCertificate() {

        try {
            // Generate root key
            System.out.println("Generating Root RSA key...");
            ca_rsa = generateKeyPair("RSA", conf.getCaKeyLength() > 2047 ? conf.getCaKeyLength() : 3072);
            // Now create the certificates

            Name rootIssuer;
            rootIssuer = new Name();
            rootIssuer.addRDN(ObjectID.country, conf.getCaCountry());
            rootIssuer.addRDN(ObjectID.organization, conf.getCaOrgName());
            rootIssuer.addRDN(ObjectID.organizationalUnit, conf.getCaOrgUnitName());
            rootIssuer.addRDN(ObjectID.serialNumber, conf.getCaSerialNumber());
            String modelName = conf.getCaCommonName();
            int idx = modelName.indexOf("####");
            String cName;
            if (idx > -1) {
                cName = modelName.substring(0, idx) + caName + modelName.substring(idx + 4);
            } else {
                cName = caName + " " + modelName;
            }
            rootIssuer.addRDN(ObjectID.commonName, cName);


            V3Extension[] extensions = new V3Extension[3];
            extensions[0] = new BasicConstraints(true);
            extensions[1] = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature);

            extensions[2] = getAnyCertificatePolicies();

            //
            // create self signed CA cert
            //
            X509Certificate caRoot = null;
            X509Certificate[] chain = new X509Certificate[1];
            // for verifying the created certificates

            LOG.info("create self signed RSA CA certificate...");
            GregorianCalendar date = new GregorianCalendar();
            Date notBefore = date.getTime();
            date.add(Calendar.YEAR, 5);
            Date notAfter = date.getTime();

            caRoot = createRootCertificate(rootIssuer, notBefore,notAfter,ca_rsa.getPublic(),
                    ca_rsa.getPrivate(), AlgorithmID.sha256WithRSAEncryption, extensions);
            // verify the self signed certificate
            caRoot.verify();
            // set the CA cert as trusted root
            chain[0] = caRoot;
            addToKeyStore(ca_rsa, chain, ca.getKsPassword(), ca.getKsAlias());
            //System.out.println(caRoot.toString());
            //rootIssuer.removeRDN(ObjectID.commonName);

        } catch (Exception ex) {
            LOG.warning(ex.getMessage());
        }
    }

    protected static X509Certificate createRootCertificate(Name subjectIssuer, Date notBefore, Date notAfter, PublicKey publicKey,
            PrivateKey privateKey, AlgorithmID algorithm, V3Extension[] extensions) {

        // create a new certificate
        X509Certificate cert = new X509Certificate();

        try {
            // set the values
            cert.setSerialNumber(new BigInteger("1"));  //new BigInteger(20, new Random())
            cert.setSubjectDN(subjectIssuer);
            cert.setPublicKey(publicKey);
            cert.setIssuerDN(subjectIssuer);
            cert.setValidNotBefore(notBefore);
            cert.setValidNotAfter(notAfter);
            if (extensions != null) {
                for (int i = 0; i < extensions.length; i++) {
                    cert.addExtension(extensions[i]);
                }
            }
            cert.addExtension(new SubjectKeyIdentifier(publicKey));
            // and sign the certificate
            cert.sign(algorithm, privateKey);
        } catch (Exception ex) {
            LOG.warning("Error creating the certificate: " + ex.getMessage());
            return null;
        }
        return cert;
    }

    /**
     * Add the private key and the certificate chain to the key store.
     */
    public void addToKeyStore(KeyPair keyPair, X509Certificate[] chain, char[] ksPassword, String alias) throws KeyStoreException {
        key_store.setKeyEntry(alias, keyPair.getPrivate(), ksPassword, chain);
    }

    private void saveKeyStore(char[] ksPassword) {
        try {
            // write the KeyStore to disk
            FileOutputStream os = new FileOutputStream(keyStoreFile);
            key_store.store(os, ksPassword);
            os.close();
        } catch (Exception ex) {
            LOG.warning("Error saving KeyStore! " + ex.getMessage());
        }
    }

    protected static CertificatePolicies getAnyCertificatePolicies() {
        PolicyInformation policyInformation = new PolicyInformation(ObjectID.anyPolicy, null);
        CertificatePolicies certificatePolicies = new CertificatePolicies(new PolicyInformation[]{policyInformation});
        return certificatePolicies;
    }
}
