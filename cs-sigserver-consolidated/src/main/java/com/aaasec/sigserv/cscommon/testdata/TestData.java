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
package com.aaasec.sigserv.cscommon.testdata;

import com.aaasec.sigserv.cscommon.DocTypeIdentifier;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.enums.SigDocumentType;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class provides functions for collecting test data and storing this test data into a test data folder.
 * These methods are called from appropriate places in the project. In order to activate test data collection,
 * set the static boolean storeTestData to true.
 */
public class TestData {

    private static final String dataDir = "/Library/Application Support/EidSigServer/testdata/";
    private static String keyStorePassword = "password";
    private static String keyStoreAlias = "sign";
    private static Map<String, KeyPair> keyPairMap = new HashMap<String, KeyPair>();
    private static Map<String, String> algoMap = new HashMap<String, String>();
    private static boolean storeTestData = false;

    /**
     * Dummy constructor preventing instantiation
     */
    private TestData() {
    }

    /**
     * Is test data storage activated
     * @return true is test data is activated
     */
    public static boolean isStoreTestData() {
        return storeTestData;
    }

    /**
     * Activate or turn off test data storage.
     * @param storeTestData set to true to activate test data storage.
     */
    public static void setStoreTestData(boolean storeTestData) {
        TestData.storeTestData = storeTestData;
    }

    /**
     * Set the password for stored keystores.
     * @param keyStorePassword Key store password
     */
    public static void setKeyStorePassword(String keyStorePassword) {
        TestData.keyStorePassword = keyStorePassword;
    }

    /**
     * Set the alias for the stored keys and certificate
     * @param keyStoreAlias Alias
     */
    public static void setKeyStoreAlias(String keyStoreAlias) {
        TestData.keyStoreAlias = keyStoreAlias;
    }        

    /**
     * Store sign request
     * @param id Sign request id
     * @param sigRequest Sign request
     */
    public static void storeSigRequest(String id, byte[] sigRequest) {
        if (!storeTestData){
            return;
        }
        FileOps.saveByteFile(sigRequest, DataType.sigRequest.getFile(id));
    }

    /**
     * Store request XHTML
     * @param id Sign request id
     * @param xhtml Sign request xhtml
     */
    public static void storeXhtmlRequest(String id, String xhtml) {
        if (!storeTestData){
            return;
        }
        FileOps.saveTxtFile(DataType.requestXhtml.getFile(id), xhtml);
    }

    /**
     * Store the algorithm of the stored keys and certificate. Allowed values
     * are "rsa" or "ecdsa"
     * @param id Sign request id
     * @param rsa 
     */
    public static void storeAlgo(String id, String algorithmName) {
        if (!storeTestData){
            return;
        }
        algoMap.put(id, algorithmName);
    }

    /**
     * Store ecdsa key pair
     * @param id Sign request id
     * @param kp Key pair
     */
    public static void storeEcdsaKeyPair(String id, KeyPair kp) {
        if (!storeTestData){
            return;
        }
        keyPairMap.put(id, kp);
    }

    /**
     * Store user certificate together with key pair in a keystore. A call to the storeAlgo
     * and either storeEcdsaKeyPair or storeRsaKeyPair must be called before calling this
     * method.
     * @param id Sign request id
     * @param encodedCert 
     */
    public static void storeUserCert(String id, byte[] encodedCert) {
        if (!storeTestData){
            return;
        }
        String algo = "";
        DataType dataType;
        KeyPair kp;

        if (algoMap.containsKey(id)) {
            algo = algoMap.get(id);
            algoMap.remove(id);
        }
        if (algo.equalsIgnoreCase("rsa")) {
            dataType = DataType.rsaKeyStore;
        } else {
            dataType = DataType.ecdsaKeyStore;
        }

        if (keyPairMap.containsKey(id)) {
            kp = keyPairMap.get(id);
            keyPairMap.remove(id);
            createKeyStore(dataType.getFile(id), kp, getCertificate(encodedCert));
        }
    }

    /**
     * Store sign response xhtml
     * @param id Sign request id
     * @param xhtml Sign response xhtml
     */
    public static void storeXhtmlResponse(String id, String xhtml) {
        if (!storeTestData){
            return;
        }
        FileOps.saveTxtFile(DataType.responseXhtml.getFile(id), xhtml);
    }

    /**
     * Store sign response
     * @param id Sign request id
     * @param signedResponse Sign response
     */
    public static void storeResponse(String id, byte[] signedResponse) {
        if (!storeTestData){
            return;
        }
        FileOps.saveByteFile(signedResponse, DataType.signResponse.getFile(id));
    }

    /**
     * Store the SAML assertion used to authenticate the signer
     * @param id Sign request id
     * @param assertions SAML assertion
     */
    public static void storeAssertions(String id, List<byte[]> assertions) {
        if (!storeTestData){
            return;
        }
        for (int i = 0; i < assertions.size(); i++) {
            String fName = DataType.signerAssertion.getFileName(id) + "_" + String.valueOf(i) + ".xml";
            byte[] assertion = assertions.get(i);
            FileOps.saveByteFile(assertion, new File(fName));
        }
    }

    /**
     * Store the document to be signed
     * @param id Sign request id
     * @param document Document to be signed
     */
    public static void storeDocTbs(String id, byte[] document) {
        if (!storeTestData){
            return;
        }
        FileOps.saveByteFile(document, getDocTypeFile(id, document, DataType.tbsDoc));
    }

    /**
     * Store signed document
     * @param id Sign request id
     * @param signedDoc document to be signed
     */
    public static void storeSignedDoc(String id, byte[] signedDoc) {
        if (!storeTestData){
            return;
        }
        FileOps.saveByteFile(signedDoc, getDocTypeFile(id, signedDoc, DataType.sigedDoc));
    }

    /**
     * Store RSA key pair
     * @param id Sign request id
     * @param kp RSA key pair
     */
    public static void storeRSAKeyPair(String id, KeyPair kp) {
        if (!storeTestData){
            return;
        }
        keyPairMap.put(id, kp);
    }

    private static void createKeyStore(File keyStoreFile, KeyPair keyPair, X509Certificate cert) {
        String pwd = "password";
        String alias = "sign";
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);
            X509Certificate[] chain = new X509Certificate[]{cert};
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), pwd.toCharArray(), chain);
            FileOutputStream os = new FileOutputStream(keyStoreFile);
            keyStore.store(os, pwd.toCharArray());
            os.close();
        } catch (Exception ex) {
        }
    }

    private static X509Certificate getCertificate(byte[] certBytes) {
        X509Certificate cert = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (java.security.cert.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (CertificateException ex) {
            Logger.getLogger(TestData.class.getName()).log(Level.SEVERE, null, ex);
        }
        return cert;
    }

    private static File getDocTypeFile(String id, byte[] docBytes, DataType dataType) {
        String fName = dataType.getFileName(id);
        SigDocumentType docType = DocTypeIdentifier.getDocType(docBytes);
        switch (docType) {
            case XML:
                fName = fName + ".xml";
                break;
            case PDF:
                fName = fName + ".pdf";
                break;
            case Unknown:
                break;
            default:
                throw new AssertionError(docType.name());
        }

        return new File(fName);
    }

    private enum DataType {

        tbsDoc("_tbs_doc"),
        sigedDoc("_signedDoc"),
        rsaKeyStore("_rsa_keystore.jks"),
        ecdsaKeyStore("_ecdsa_keystore.jks"),
        sigRequest("_sign_request.xml"),
        signResponse("_sign_response.xml"),
        signerAssertion("_signer_assertion"),
        requestXhtml("_request_xhtml.xhtml"),
        responseXhtml("_response_xhtml.xhtml");
        private String fileExt;

        private DataType(String fileExt) {
            this.fileExt = fileExt;
        }

        public String getFileExt() {
            return fileExt;
        }

        public File getFile(String id) {
            String fileName = getFileName(id);
            File file = new File(fileName);
            return file;
        }

        public String getFileName(String id) {
            String fileName = dataDir + id + fileExt;
            return fileName;
        }
    }
}
