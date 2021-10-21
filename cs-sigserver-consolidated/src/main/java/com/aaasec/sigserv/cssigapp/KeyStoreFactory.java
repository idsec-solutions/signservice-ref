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
package com.aaasec.sigserv.cssigapp;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.FilenameFilterImpl;
import com.aaasec.sigserv.cscommon.FnvHash;
import com.aaasec.sigserv.cscommon.testdata.TestData;
import com.aaasec.sigserv.cssigapp.centralsig.SupportedSigAlgoritm;
import com.aaasec.sigserv.cssigapp.models.SigServerModel;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Key store factory
 */
public class KeyStoreFactory {

    private static final Logger LOG = Logger.getLogger(KeyStoreFactory.class.getName());
    public static final String K_NAME = "ROOT";
    SigServerModel model;
    String keyStoreDir;
    String tempKeyStoreDir;
    String dbFileName;
    Thread stThread;
    StackUpKeyStores ksGenerator;
    FilenameFilterImpl noLeadingDot = new FilenameFilterImpl(".");
    Random rng = new Random(System.currentTimeMillis());

    public KeyStoreFactory(SigServerModel model) {
        this.model = model;
        keyStoreDir = FileOps.getfileNameString(model.getDataLocation(), "keystores");
        tempKeyStoreDir = FileOps.getfileNameString(model.getDataLocation(), "temp_keystores");
        FileOps.createDir(keyStoreDir);
        FileOps.createDir(tempKeyStoreDir);
        ksGenerator = new StackUpKeyStores();
    }

    /**
     * Make sure that the key store collection includes at least one unreserved
     * key pair.
     */
    private int countKs() {
        File[] listFiles = new File(keyStoreDir).listFiles(noLeadingDot);
        return listFiles.length;
    }

    private boolean running(Thread thread) {
        return (thread != null && thread.isAlive());
    }

    public void stackUp() {
        if (running(stThread)) {
            return;
        }
        stThread = new Thread(ksGenerator);
        stThread.setDaemon(true);
        stThread.start();
    }

    private void createNewKeyStore() {
        BigInteger id = new BigInteger(64, new Random(System.currentTimeMillis()));
        File ksFile = new File(keyStoreDir, id.toString(16));
        createKeyStore(ksFile);
    }

    private void createKeyStore(File keyStoreFile) {
        String id = keyStoreFile.getName();
        try {
            KeyStore key_store = KeyStore.getInstance("JKS");
            key_store.load(null, null);
            generateV1Certificate(id, getKsPass(id), key_store);
            saveKeyStore(key_store, keyStoreFile, id);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, null, ex);
        }
    }

    /**
     * Generate a 2048 bit RSA KeyPair.
     *
     * @param algorithm the algorithm to use
     * @param bits the length of the key (modulus) in bits
     *
     * @return the KeyPair
     *
     * @exception NoSuchAlgorithmException if no KeyPairGenerator is available
     * for the requested algorithm
     */
    private static KeyPair generateKeyPair()
            throws NoSuchAlgorithmException {

        KeyPair kp = null;
        KeyPairGenerator generator;
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        kp = generator.generateKeyPair();
        return kp;
    }

    private static KeyPair generateECDSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("P-256");

        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();
        return pair;
    }

    private void saveKeyStore(KeyStore key_store, File keyStoreFile, String id)
            throws FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        char[] ksPassword = getKsPass(id);

        // write the KeyStore to disk
        FileOutputStream os = new FileOutputStream(keyStoreFile);
        key_store.store(os, ksPassword);
        os.close();
    }

    private char[] getKsPass(String ksID) {
        return FnvHash.getFNV1aToHex(ksID + "1ikjEuIWdf%&(/=jh2#€").toCharArray();
    }

    private KeyStore getKeyStore(File keyStoreFile, String id) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore key_store;

        key_store = KeyStore.getInstance("JKS");
        key_store.load(new FileInputStream(keyStoreFile), getKsPass(id));
        return key_store;
    }

    public X509Certificate generateV1Certificate(String subject, char[] ksPass, KeyStore keyStore) throws OperatorCreationException, IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
        KeyPair pair = generateKeyPair();

        BigInteger certSerial = BigInteger.valueOf(System.currentTimeMillis());
        X500Name issuerDN = new X500Name("CN=" + subject);
        X500Name subjectDN = new X500Name("CN=" + subject);
        Date notBefore = new Date(System.currentTimeMillis() - 10000);
        Date notAfter = new Date(System.currentTimeMillis() + 10000);
        PublicKey pubKey = (pair.getPublic());
        X509v1CertificateBuilder certGen = new JcaX509v1CertificateBuilder(issuerDN, certSerial, notBefore, notAfter, subjectDN, pubKey);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHRSA").build(pair.getPrivate());
        byte[] encoded = certGen.build(signer).getEncoded();
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(encoded);
        X509Certificate generateCertificate = (X509Certificate) fact.generateCertificate(is);
        is.close();

        // set the CA cert as trusted root
        X509Certificate[] chain = new X509Certificate[]{generateCertificate};
        addToKeyStore(pair, chain, K_NAME, keyStore, ksPass);

        String certStr = generateCertificate.toString();

        return generateCertificate;
    }

    /**
     * Add the private key and the certificate chain to the key store.
     */
    public void addToKeyStore(KeyPair keyPair, X509Certificate[] chain, String alias, KeyStore key_store, char[] KS_PASSWORD) throws KeyStoreException {
        key_store.setKeyEntry(alias, keyPair.getPrivate(), KS_PASSWORD, chain);
    }

    public void cleanup() {
        FileUtils.deleteQuietly(new File(tempKeyStoreDir));
        FileOps.createDir(tempKeyStoreDir);
    }

    public KeyStoreObjects getKeyStoreObjects(String reserver) {
        String keyStoreId = "";
        File privateKsFile = new File(tempKeyStoreDir, reserver);
        File[] listFiles = new File(keyStoreDir).listFiles(noLeadingDot);
        int cnt = listFiles.length;
        int select = Math.abs(rng.nextInt(cnt));
        File selected;
        boolean success = false;
        // try to claim a ks file;
        try {
            selected = listFiles[select];
            keyStoreId = selected.getName();
            selected.renameTo(privateKsFile);
            success = privateKsFile.canRead();
        } catch (Exception ex) {
        }
        // If not successful - generate a new key store
        if (!success) {
            createKeyStore(privateKsFile);
            keyStoreId = reserver;
        }

        try {
            KeyStore ks = getKeyStore(privateKsFile, keyStoreId);
            PrivateKey pk = (PrivateKey) ks.getKey(K_NAME, getKsPass(keyStoreId));
            Certificate cert = ks.getCertificate(K_NAME);
            iaik.x509.X509Certificate x509cert = CertificateUtils.getCertificate(cert.getEncoded());
            privateKsFile.delete();
            return new KeyStoreObjects(pk, x509cert);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, null, ex);
            privateKsFile.delete();
            return null;
        }
    }

    KeyPair getKeyPair(SupportedSigAlgoritm reqSigAlgo, String requestID) {
        KeyPair kp;
        switch (reqSigAlgo.getPkAlgoType()) {
            case EC:
                try {
                    kp = generateECDSAKeyPair();
                    // Save ECDSA key pair
                    TestData.storeEcdsaKeyPair(requestID, kp);
                    TestData.storeAlgo(requestID, "ECDSA");

                    return kp;
                } catch (Exception ex) {
                    Logger.getLogger(KeyStoreFactory.class.getName()).warning(ex.getMessage());
                }
                break;
            case RSA:
                KeyStoreObjects kso = getKeyStoreObjects(requestID);
                kp = new KeyPair(kso.getCert().getPublicKey(), kso.getPk());

                // Save key pair in test data
                TestData.storeRSAKeyPair(requestID, kp);
                TestData.storeAlgo(requestID, "RSA");


                return kp;
        }
        return null;
    }

    public class KeyStoreObjects {

        private PrivateKey pk;
        private X509Certificate cert;

        public KeyStoreObjects(PrivateKey pk, X509Certificate cert) {
            this.pk = pk;
            this.cert = cert;
        }

        public X509Certificate getCert() {
            return cert;
        }

        public PrivateKey getPk() {
            return pk;
        }
    }

    class StackUpKeyStores implements Runnable {

        private int maxKeyStores = 20;

        public StackUpKeyStores() {
        }

        public void run() {
            int cnt = maxKeyStores - countKs();

            for (int i = 0; i < cnt; i++) {
                createNewKeyStore();
            }
        }
    }
}
