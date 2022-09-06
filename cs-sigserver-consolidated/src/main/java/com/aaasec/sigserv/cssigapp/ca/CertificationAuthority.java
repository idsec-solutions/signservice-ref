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

import com.aaasec.lib.crypto.xml.XMLSign;
import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.FnvHash;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import com.aaasec.sigserv.cssigapp.ca.attrmapping.AttributeMapper;
import com.aaasec.sigserv.cssigapp.ca.attrmapping.AttributeMapperImpl;
import com.aaasec.sigserv.cssigapp.data.DbCALog;
import com.aaasec.sigserv.cssigapp.data.DbCAParam;
import com.aaasec.sigserv.cssigapp.data.DbCert;
import com.aaasec.sigserv.cssigapp.data.SigConfig;
import com.aaasec.sigserv.cssigapp.db.CAlogDbTable;
import com.aaasec.sigserv.cssigapp.db.CAparamDbTable;
import com.aaasec.sigserv.cssigapp.db.CertDbTable;
import com.aaasec.sigserv.cssigapp.models.SigServerModel;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.DistributionPoint;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.utils.Util;
import iaik.x509.RevokedCertificate;
import iaik.x509.V3Extension;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.X509Extensions;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.CRLDistributionPoints;
import iaik.x509.extensions.CRLNumber;
import iaik.x509.extensions.CertificatePolicies;
import iaik.x509.extensions.IssuingDistributionPoint;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.ReasonCode;
import iaik.x509.extensions.SubjectAltName;
import iaik.x509.extensions.SubjectKeyIdentifier;
import iaik.x509.extensions.qualified.QCStatements;
import iaik.x509.extensions.qualified.structures.QCStatement;
import iaik.x509.extensions.qualified.structures.QCSyntaxV2;
import iaik.x509.extensions.qualified.structures.etsi.QcEuCompliance;
import iaik.x509.extensions.qualified.structures.etsi.QcEuLimitValue;
import iaik.x509.extensions.qualified.structures.etsi.QcEuSSCD;
import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509CRLEntry;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.w3c.dom.Node;
import se.elegnamnden.id.authCont.x10.saci.SAMLAuthContextDocument;
import se.elegnamnden.id.csig.x11.dssExt.ns.CertRequestPropertiesType;
import se.elegnamnden.id.csig.x11.dssExt.ns.CertRequestPropertiesType.CertType;
import se.elegnamnden.id.csig.x11.dssExt.ns.RequestedAttributesType;

/**
 * This class implements the Certification Authority logic for a CA.
 */
public class CertificationAuthority implements CaKeyStoreConstants {

    private static final Logger LOG = Logger.getLogger(CertificationAuthority.class.getName());
    protected KeyStore key_store;
    private File keyStoreFile;
    protected char[] ksPassword;
    protected String ksAlias;
    private String caName;
    private String caID;
    protected X509Certificate caCert = null;
    private Name rootIssuer;
    private boolean initialized = false;
    private String caDir;
    private long nextSerial;
    private File crlFile;
    private File exportCrlFile;
    private File certPathFile;
    private CertPath certPath;
    protected String crlDpUrl;
    private X509CRL latestCrl = null;
    long crlValPeriod;
    private CertDbTable certDb;
    private CAlogDbTable logDb;
    private CAparamDbTable paramDb;
    private Map<String, DbCAParam> paramMap;
    private SigServerModel model;
    private final HashMap<String, String> pdsUrl = new HashMap<String, String>();
    private SigConfig conf;
    private static Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public CertificationAuthority(String cAName, String caDir, SigServerModel model, char[] ksPassword, String ksAlias) {
        this.caName = cAName;
        this.caID = FnvHash.getFNV1aToHex(caName);
        this.caDir = caDir;
        this.model = model;
        this.ksPassword = ksPassword;
        this.ksAlias = ksAlias;
        conf = model.getConf();
        crlValPeriod = (long) conf.getCrlValidityHours() * (1000 * 60 * 60);
        keyStoreFile = new File(this.caDir, "ca.keystore");
        crlFile = new File(caDir, caID + ".crl");
        certPathFile = new File(caDir, "certPath.json");
        exportCrlFile = new File(FileOps.getfileNameString(ContextParameters.getCompleteCaFileSorageLocation(), "crl"), caID + ".crl");
        crlDpUrl = FileOps.getfileNameString(ContextParameters.getPublicationUrl(), "crl") + "/" + caID + ".crl";
        pdsUrl.put("sv", FileOps.getfileNameString(ContextParameters.getPublicationUrl(), "pds") + "/" + caID + "-sv.html");
        pdsUrl.put("en", FileOps.getfileNameString(ContextParameters.getPublicationUrl(), "pds") + "/" + caID + "-en.html");

        //Init DB
        String dbFileName = FileOps.getfileNameString(caDir, cAName + ".db");
        certDb = new CertDbTable(dbFileName);
        logDb = new CAlogDbTable(dbFileName);
        paramDb = new CAparamDbTable(dbFileName);

        //Register private QCStatements
        QCStatement.register(PdsQCStatement.statementID, PdsQCStatement.class);
        QCStatement.register(AuthContextQCStatement.statementID, AuthContextQCStatement.class);
        X509Extensions.register(AuthContextExtension.extensionOid, AuthContextExtension.class);

        //Init CA
        initKeyStore();
    }

    public final boolean initKeyStore() {
        try {
            if (keyStoreFile.canRead()) {
                key_store = KeyStore.getInstance("JKS");
//                key_store = KeyStore.getInstance("IAIKKeyStore", "IAIK");
                key_store.load(new FileInputStream(keyStoreFile), ksPassword);
                if (crlFile.canRead()) {
                    latestCrl = new X509CRL(new FileInputStream(crlFile));
                }
                X509Certificate root = getSelfSignedCert();
                if (root != null) {
                    initialized = true;
                }
            }
        } catch (Exception ex) {
            LOG.log(Level.WARNING, null, ex);
        }
        return initialized;
    }

    public X509Certificate getSelfSignedCert() {
        try {
            X509Certificate cert = Util.convertCertificate(key_store.getCertificate(ksAlias));
            caCert = cert;
        } catch (Exception ex) {
            LOG.warning(ex.getMessage());
            caCert = null;
        }
        return caCert;
    }

    public char[] getKsPassword() {
        return ksPassword;
    }

    public String getKsAlias() {
        return ksAlias;
    }

    public String getCaName() {
        return caName;
    }

    public String getCaDir() {
        return caDir;
    }

    public String getCaID() {
        return caID;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public X509CRL getLatestCrl() {
        return latestCrl;
    }

    public File getExportCrlFile() {
        return exportCrlFile;
    }

    public File getCrlFile() {
        return crlFile;
    }

    public CertPath getCertPath() {
        certPath = null;
        if (certPathFile.canRead()) {
            String json = FileOps.readTextFile(certPathFile);
            certPath = gson.fromJson(json, CertPath.class);
        }
        return certPath;
    }

    public void setCertPath(CertPath certPath) {
        this.certPath = certPath;
        if (certPath != null) {
            String json = gson.toJson(certPath);
            FileOps.saveTxtFile(certPathFile, json);
        } else {
            certPathFile.delete();
        }
    }

    /**
     * Returns a complete path from a user certificate issued by this CA up to
     * the configured root certificate.
     *
     * @param userCert an end entity user certificate issued by this CA
     * @return a certificate path array with the user certificate at index 0 and
     * the root certificate at the last index.
     */
    public X509Certificate[] getChain(X509Certificate userCert) {
        List<X509Certificate> certPathList = new ArrayList<X509Certificate>();
        if (userCert != null) {
            certPathList.add(userCert);
        }
        CertPath cp = getCertPath();
        if (cp == null) {
            certPathList.add(caCert);
        } else {
            for (String pem : cp.getCertPath()) {
                try {
                    X509Certificate cert = CertificateUtils.getCertificate(pem);
                    if (cert != null) {
                        certPathList.add(cert);
                    }
                } catch (Exception ex) {
                }
            }
        }

        return certPathList.toArray(new X509Certificate[certPathList.size()]);
    }

    /**
     * Returns the current certificate path from the CA certificate of this ca
     * up to the configured root certificate (if any)
     *
     * @return A certificate path with the CA certificate at index 0 and the
     * root certificate at the last index.
     */
    public X509Certificate[] getChain() {
        return getChain(null);
    }

    public X509Certificate issueUserCert(AuthData userInfo, PublicKey userPk, CertRequestPropertiesType certReqProp, String spServiceId) {
        RequestedAttributesType reqAttrType = null;
        CertType.Enum certType = CertType.PKC;

        if (certReqProp != null) {
            reqAttrType = certReqProp.getRequestedCertAttributes();
            certType = certReqProp.getCertType();
        }

        BigInteger certSerial = getSeededSerialNumber(userPk);

        AttributeMapper attributeMapper = new AttributeMapperImpl();
        Principal subject = attributeMapper.getSubjectName(reqAttrType, userInfo);
        if (subject == null) {
            return null;
        }
        SubjectAltName subjectAltNameExtension = attributeMapper.getSubjectAltNameExtension();

        Date notBefore = new Date(System.currentTimeMillis() - (1000 * 60 * 10));
        Calendar na = Calendar.getInstance();
        na.setTime(notBefore);
        na.add(Calendar.YEAR, 1);
        Date notAfter = na.getTime();

        List<V3Extension> extList = new LinkedList<V3Extension>();
        extList.add(new BasicConstraints(false));
        extList.add(getCertificatePolicy(POLICY_QCSSCD));
        if (!certType.equals(CertType.PKC)) {
            extList.add(getQcStatements(userInfo, attributeMapper, certType));
        }

        SAMLAuthContextDocument simpleAssertionInfo = userInfo.getSimpleAssertionInfo();
        if (spServiceId!=null) {
            simpleAssertionInfo.getSAMLAuthContext().getAuthContextInfo().setServiceID(spServiceId);
        }
        extList.add(new AuthContextExtension(attributeMapper.getSamlAssertionInfo(simpleAssertionInfo)));
        extList.add(new KeyUsage(KeyUsage.nonRepudiation));
        if (subjectAltNameExtension != null) {
            extList.add(subjectAltNameExtension);
        }

        X509Certificate userCert = createCertificate(subject, userPk, notBefore, notAfter,
                certSerial, caCert, AlgorithmID.sha256WithRSAEncryption, extList);

        if (userCert != null) {
            updateCaLogOnIssue(userCert);
        }
//        LOG.info(userCert.toString(true));
        return userCert;
    }

    public void updateCaLogOnIssue(X509Certificate userCert) {
        // Store cert
        certDb.addOrReplaceRecord(new DbCert(userCert));
        // Update log
        DbCALog caLog = new DbCALog();
        caLog.setLogCode(ISSUE_EVENT);
        caLog.setEventString("Certificate issued");
        DbCALog.Parameters param = new DbCALog.Parameters();
        param.serial = userCert.getSerialNumber();
        caLog.setLogParameter(model.getGson().toJson(param));
        caLog.setLogTime(System.currentTimeMillis());
        logDb.addOrReplaceRecord(caLog);
//Store next serial number
//        DbCAParam cp = paramDb.getDbRecord(CERT_SERIAL_KEY);
//        cp.setIntValue(nextSerial + 1);
//        paramDb.addOrReplaceRecord(cp);
    }

    protected BigInteger getSeededSerialNumber(PublicKey pk) {
        String seed = String.valueOf(Base64Coder.encode(pk.getEncoded())) + new BigInteger(64, new Random(System.currentTimeMillis())).toString(16);
        BigInteger serial = new BigInteger(128, new Random(System.currentTimeMillis()));
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] digest = sha1.digest(seed.getBytes());
            byte[] cut = new byte[16];
            System.arraycopy(digest, 0, cut, 0, 16);
            cut[0] = (byte) ((int) cut[0] & 127);
            serial = new BigInteger(cut);
        } catch (NoSuchAlgorithmException ex) {
        }
        return serial;
    }

    private X509Certificate createCertificate(Principal subject, PublicKey pk,
            Date notBefore, Date notAfter, BigInteger certSerial,
            X509Certificate issuerCert, AlgorithmID algorithm, List<V3Extension> extensions) {

        // create a new certificate
        X509Certificate cert = new X509Certificate();
        PublicKey publicKey = pk;

        try {
            // set cert values
            cert.setSerialNumber(certSerial);
            cert.setSubjectDN(subject);
            cert.setPublicKey(publicKey);
            cert.setIssuerDN(issuerCert.getSubjectDN());
            cert.setValidNotBefore(notBefore);
            if (issuerCert.getNotAfter().after(notAfter)) {
                cert.setValidNotAfter(notAfter);
            } else {
                cert.setValidNotAfter(issuerCert.getNotAfter());
            }

            // Add provided extensions
            for (V3Extension extension : extensions) {
                cert.addExtension(extension);
            }
            // Add AKI
            byte[] keyID = ((SubjectKeyIdentifier) issuerCert.getExtension(SubjectKeyIdentifier.oid)).get();
            cert.addExtension(new AuthorityKeyIdentifier(keyID));

            // Add SKI
            cert.addExtension(new SubjectKeyIdentifier(pk));

            //Add Crl distribution point
            String[] uriStrings = new String[]{crlDpUrl};
            DistributionPoint distPoint = new DistributionPoint();
            distPoint.setDistributionPointNameURIs(uriStrings);
            cert.addExtension(new CRLDistributionPoints(distPoint));

            // and sign the certificate
            cert.sign(algorithm, (PrivateKey) key_store.getKey(ksAlias, ksPassword));
        } catch (Exception ex) {
            cert = null;
            LOG.warning("Error creating the certificate: " + ex.getMessage());
        }

        return cert;
    }

//    /**
//     * Add the private key and the certificate chain to the key store.
//     */
//    public void addToKeyStore(KeyPair keyPair, X509Certificate[] chain, String alias) throws KeyStoreException {
//        key_store.setKeyEntry(alias, keyPair.getPrivate(), KS_PASSWORD, chain);
//    }
//
//    private void saveKeyStore() {
//        try {
//            // write the KeyStore to disk
//            FileOutputStream os = new FileOutputStream(keyStoreFile);
//            key_store.store(os, KS_PASSWORD);
//            os.close();
//        } catch (Exception ex) {
//            LOG.warning("Error saving KeyStore! " + ex.getMessage());
//        }
//    }
    private CertificatePolicies getDefCertificatePolicies() {
        PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(null, null, "This certificate may be used for demonstration purposes only.");
        PolicyInformation policyInformation = new PolicyInformation(new ObjectID("1.3.6.1.4.1.2706.2.2.1.1.1.1.1"), new PolicyQualifierInfo[]{policyQualifierInfo});
        CertificatePolicies certificatePolicies = new CertificatePolicies(new PolicyInformation[]{policyInformation});
        return certificatePolicies;
    }

    protected CertificatePolicies getAnyCertificatePolicies() {
        PolicyInformation policyInformation = new PolicyInformation(ObjectID.anyPolicy, null);
        CertificatePolicies certificatePolicies = new CertificatePolicies(new PolicyInformation[]{policyInformation});
        return certificatePolicies;
    }

    public byte[] signResponse(byte[] xmlData, Node sigParent) throws Exception {
        return XMLSign.getSignedXML(xmlData, (PrivateKey) key_store.getKey(ksAlias, ksPassword), caCert, sigParent, true, false).sigDocBytes;
    }

    /**
     * Revokes certificates marked for revocation in the certificate database
     *
     * @return the number of certificates being revoked by this action.
     */
    public int revokeCertificates() {
        long currentTime = System.currentTimeMillis();
        long nextUpdateTime = currentTime + crlValPeriod;
        List<DbCert> certList = certDb.getCertsByRevocation(true);

        DbCAParam cp = paramDb.getDbRecord(CRL_SERIAL_KEY);
        if (cp == null) {
            return 0;
        }
        long nextCrlSerial = cp.getIntValue();

        try {

            int previoslyRevoked = (latestCrl == null) ? 0 : latestCrl.getRevokedCertificates().size();

            X509CRL crl = new X509CRL();

            crl.setIssuerDN((Name) caCert.getSubjectDN());
            crl.setThisUpdate(new Date(currentTime));
            crl.setNextUpdate(new Date(nextUpdateTime));
            crl.setSignatureAlgorithm(AlgorithmID.sha256WithRSAEncryption);

            // Add AKI
            byte[] keyID = ((SubjectKeyIdentifier) caCert.getExtension(SubjectKeyIdentifier.oid)).get();
            crl.addExtension(new AuthorityKeyIdentifier(keyID));

            // CRLNumber to be adjusted to an incremental number
            CRLNumber cRLNumber = new CRLNumber(BigInteger.valueOf(nextCrlSerial));
            crl.addExtension(cRLNumber);

            // IssuingDistributionPoint
            GeneralNames distributionPointName = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlDpUrl));
            IssuingDistributionPoint issuingDistributionPoint = new IssuingDistributionPoint();
            issuingDistributionPoint.setDistributionPointName(distributionPointName);

            issuingDistributionPoint.setCritical(true);
            //issuingDistributionPoint.setOnlyContainsCaCerts(true);
            crl.addExtension(issuingDistributionPoint);

            for (DbCert dbCert : certList) {
                GregorianCalendar revTime = new GregorianCalendar();
                RevokedCertificate rc = new RevokedCertificate(dbCert.getCertificate(), new Date(dbCert.getRevDate()));

                // ReasonCode
                rc.addExtension(new ReasonCode(ReasonCode.privilegeWithdrawn));
                crl.addCertificate(rc);

            }


            crl.sign((PrivateKey) key_store.getKey(ksAlias, ksPassword));

            byte[] crlBytes = crl.toByteArray();
            // send CRL to ...
            iaik.utils.Util.saveToFile(crlBytes, crlFile.getAbsolutePath());
            logRevocation(certList);

            // receive CRL
            latestCrl = new X509CRL(crlBytes);
            cp.setIntValue(nextCrlSerial + 1);
            paramDb.addOrReplaceRecord(cp);
            //System.out.println(newCrl.toString(true));
            // Store CRL
            FileOps.saveByteFile(FileOps.readBinaryFile(crlFile), exportCrlFile);
//            FTPops.uploadCRL(caName, caDir);
            return certList.size() - previoslyRevoked;

        } catch (Exception ex) {
            LOG.warning(ex.getMessage());
            return 0;
        }
    }

    public void revokeCertificate(BigInteger certSerial) {
        DbCert dBcert = getCertificateBySerial(certSerial);
        if (dBcert.getRevoked() == 0) {
            dBcert.setRevoked(1);
            dBcert.setRevDate(System.currentTimeMillis());
            certDb.addOrReplaceRecord(dBcert);
        }
    }

    public void logRevocation(List<DbCert> revCertList) {
        List<BigInteger> crlList = new LinkedList<BigInteger>();
        if (latestCrl != null) {
            Enumeration crlEntries = latestCrl.listCertificates();

            while (crlEntries.hasMoreElements()) {
                BigInteger revokedSerial = ((X509CRLEntry) crlEntries.nextElement()).getSerialNumber();
                crlList.add(revokedSerial);
            }
        }

        for (DbCert dbCert : revCertList) {
            if (!crlList.contains(dbCert.getSerial())) {
                //update log 
                DbCALog caLog = new DbCALog();
                caLog.setLogCode(REVOKE_EVENT);
                caLog.setEventString("Certificate revoked");
                DbCALog.Parameters param = new DbCALog.Parameters();
                param.serial = dbCert.getSerial();
                param.reason = ReasonCode.privilegeWithdrawn;
                caLog.setLogParameter(model.getGson().toJson(param));
                caLog.setLogTime(dbCert.getRevDate());
                logDb.addOrReplaceRecord(caLog);
            }
        }
    }

    public List<DbCert> getAllCertificates() {
        return certDb.getAllRecords();
    }

    public List<DbCert> getAllCertificates(boolean revoked) {
        return certDb.getRecords("Revoked", (revoked) ? "1" : "0");
    }

    public DbCert getCertificateBySerial(BigInteger serial) {
        try {
            return certDb.getRecords("Serial", String.valueOf(serial)).get(0);
        } catch (Exception ex) {
        }
        return null;
    }

    public void replaceCertificateData(DbCert certData) {
        certDb.addOrReplaceRecord(certData);
    }

    public List<DbCALog> getCertLogs() {
        return logDb.getAllRecords();
    }

    public List<DbCALog> getCertLogs(int eventType) {
        return logDb.getRecords("Code", String.valueOf(eventType));
    }

    public String getFormatedLogList() {
        return getFormattedLogList(getCertLogs());
    }

    public String getFormattedLogList(int eventType) {
        return getFormattedLogList(getCertLogs(eventType));
    }

    public String getFormattedLogList(List<DbCALog> logs) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd   HH:mm:ss");
        GregorianCalendar gc = new GregorianCalendar();
        StringBuilder b = new StringBuilder();
        for (DbCALog log : logs) {
            gc.setTimeInMillis(log.getLogTime());
            DbCALog.Parameters param = model.getGson().fromJson(log.getLogParameter(), DbCALog.Parameters.class);
            b.append(dateFormat.format(gc.getTime()));
            b.append("    ");
            b.append(log.getEventString());
            b.append(" -- ");
            if (log.getLogCode() == ISSUE_EVENT) {
                b.append("Certificate Serial Number=").append(param.serial);
            }
            if (log.getLogCode() == REVOKE_EVENT) {
                b.append("Certificate Serial Number=").append(param.serial);
                b.append(", Revocation Reason=");
                long rc = param.reason;
                b.append((rc < 11) ? REV_REASON[(int) rc] : String.valueOf(rc));
            }
            b.append((char) 10);
        }
        return b.toString();
    }

    private static CertificatePolicies getCertificatePolicy(String oid) {
        PolicyInformation policyInformation = new PolicyInformation(new ObjectID(oid), null);
        CertificatePolicies certificatePolicies = new CertificatePolicies(new PolicyInformation[]{policyInformation});
        return certificatePolicies;
    }

    private static Name getSubjectName(AuthData user) {

        Name subject = new Name();
        subject.addRDN(ObjectID.country, "SE");
        subject.addRDN(ObjectID.serialNumber, user.getId());
        addNameRdn(subject, ObjectID.locality, getAttributeValue(user, "l"));
        addNameRdn(subject, ObjectID.organization, getAttributeValue(user, "o"));
        addNameRdn(subject, ObjectID.organizationalUnit, getAttributeValue(user, "ou"));
        addNameRdn(subject, ObjectID.commonName, getAttributeValue(user, new String[]{"cn", "displayName"}));
        addNameRdn(subject, ObjectID.surName, getAttributeValue(user, "sn"));
        addNameRdn(subject, ObjectID.givenName, getAttributeValue(user, "givenName"));
        addNameRdn(subject, ObjectID.title, getAttributeValue(user, "title"));
        addNameRdn(subject, ObjectID.emailAddress, getAttributeValue(user, "mail"));
        addNameRdn(subject, ObjectID.streetAddress, getAttributeValue(user, "street"));
        addNameRdn(subject, ObjectID.postalCode, getAttributeValue(user, "postalCode"));

        return subject;
    }

    private static String getAttributeValue(AuthData user, String attribute) {
        return getAttributeValue(user, new String[]{attribute});
    }

    private static String getAttributeValue(AuthData user, String[] attributes) {
        List<List<String>> userAttr = user.getAttribute();

        for (String matchAttr : attributes) {
            for (List<String> attr : userAttr) {
                try {
                    if (attr.get(0).equals(matchAttr)) {
                        return attr.get(2);
                    }
                } catch (Exception ex) {
                }
            }
        }
        return "";
    }

    private QCStatements getQcStatements(AuthData user, AttributeMapper attrMapper, CertType.Enum certType) {
        ObjectID semID = new ObjectID("1.2.752.59.54138.1.1");
        GeneralName[] genNames = new GeneralName[]{
            new GeneralName(GeneralName.uniformResourceIdentifier, "http://www.elegnamnden.se/2012/centralsig/1.0")
        };
        QCSyntaxV2 qcSyntaxV2 = new QCSyntaxV2(semID, genNames);

//        SamlAssertionInfo saInfo = attrMapper.getSamlAssertionInfo(user.getSimpleAssertionInfo());
        QCStatement[] qcStatements;

        if (certType.equals(CertType.QC_SSCD)) {
            qcStatements = new QCStatement[]{
                new QCStatement(new QcEuCompliance()),
                new QCStatement(new QcEuSSCD()),
                new QCStatement(new QcEuLimitValue("SEK", 0, 0)),
                new QCStatement(new PdsQCStatement(pdsUrl))
            };
        } else {
            qcStatements = new QCStatement[]{
                new QCStatement(new QcEuCompliance()),
                new QCStatement(new QcEuLimitValue("SEK", 0, 0)),
                new QCStatement(new PdsQCStatement(pdsUrl))
            };
        }

        QCStatements qcExt = new QCStatements(qcStatements);
        return qcExt;
    }

    private static void addNameRdn(Name subject, ObjectID oid, String value) {
        if (value.length() > 0) {
            subject.addRDN(oid, value);
        }
    }

    @Override
    public String toString() {
        return caName;
    }

    public CertDbTable getCertDb() {
        return certDb;
    }

    public long getCrlValPeriod() {
        return crlValPeriod;
    }

    public File getKeyStoreFile() {
        return keyStoreFile;
    }

    public CAlogDbTable getLogDb() {
        return logDb;
    }

    public SigServerModel getModel() {
        return model;
    }

    public CAparamDbTable getParamDb() {
        return paramDb;
    }
}
