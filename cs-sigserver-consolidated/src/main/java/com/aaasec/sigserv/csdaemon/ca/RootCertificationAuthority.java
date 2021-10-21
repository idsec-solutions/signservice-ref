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
package com.aaasec.sigserv.csdaemon.ca;

import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.FnvHash;
import com.aaasec.sigserv.cssigapp.ca.CertificationAuthority;
import com.aaasec.sigserv.cssigapp.models.SigServerModel;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.DistributionPoint;
import iaik.x509.V3Extension;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityInfoAccess;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.CRLDistributionPoints;
import iaik.x509.extensions.CertificatePolicies;
import iaik.x509.extensions.IssuerAltName;
import iaik.x509.extensions.PolicyConstraints;
import iaik.x509.extensions.PolicyMappings;
import iaik.x509.extensions.SubjectKeyIdentifier;
import iaik.x509.extensions.qualified.QCStatements;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

/**
 * Root CA object class.
 */
public class RootCertificationAuthority extends CertificationAuthority {

    private static final Logger LOG = Logger.getLogger(RootCertificationAuthority.class.getName());
    private RootCaConfig rootConf;

    public RootCertificationAuthority(String cAName, String caDir, SigServerModel model, RootCaConfig rootConf, char[] ksPassword, String ksAlias) {
        super(cAName, caDir, model, ksPassword, ksAlias);
        this.rootConf = rootConf;
    }

    public X509Certificate issueXCert(X509Certificate orgCert) {

        String seed = String.valueOf(Base64Coder.encode(orgCert.getPublicKey().getEncoded())) + new BigInteger(64, new Random(System.currentTimeMillis())).toString(16);
        BigInteger certSerial = FnvHash.getFNV1a(seed);

        List<V3Extension> extList = new LinkedList<V3Extension>();
        Enumeration e = orgCert.listExtensions();

        //System.out.println("Original cert extensions:");
        //Get extensions form orgCert
        boolean policy = false;
        if (e != null) {
            while (e.hasMoreElements()) {
                V3Extension ext = (V3Extension) e.nextElement();
                //System.out.println(ext.getObjectID().getNameAndID() + " " + ext.toString());
                //Replace policy with AnyPolicy
                ObjectID extOID = ext.getObjectID();
                if (extOID == CertificatePolicies.oid) {
                    ext = getAnyCertificatePolicies();
                    policy = true;
                }
                // Ignore the following extensions
                if (extOID == IssuerAltName.oid
                        || extOID.equals(CRLDistributionPoints.oid)
                        || extOID.equals(AuthorityInfoAccess.oid)
                        || extOID.equals(AuthorityKeyIdentifier.oid)
                        || extOID.equals(PolicyConstraints.oid)
                        || extOID.equals(PolicyMappings.oid)
                        || extOID.equals(QCStatements.oid)
                        || extOID.getID().equals("1.3.6.1.4.1.8301.3.5") // German signature law validation rules
                        ) {
                    continue;
                }
                extList.add(ext);
            }
        } else {
            V3Extension bc = new BasicConstraints(false);
            extList.add(bc);
            policy = true;
        }
        // If no policy in orgCert then add AnyPolicy to list
        if (!policy) {
            extList.add(getAnyCertificatePolicies());
        }

        //Copy to extension list
        V3Extension[] extensions = new V3Extension[extList.size()];
        for (int i = 0; i < extList.size(); i++) {
            V3Extension ext = extList.get(i);
            extensions[i] = ext;
        }
        X509Certificate xCert = createCertificate(orgCert, certSerial, caCert, AlgorithmID.sha256WithRSAEncryption, extensions);
        //System.out.println((char) 10 + "Issued XCert" + (char) 10 + xCert.toString(true));
        if (xCert != null) {
            updateCaLogOnIssue(xCert);
        }

        return xCert;
    }

    public X509Certificate createCertificate(X509Certificate orgCert, BigInteger certSerial,
            X509Certificate issuerCert, AlgorithmID algorithm, V3Extension[] extensions) {

        // create a new certificate
        X509Certificate cert = new X509Certificate();
        PublicKey publicKey = orgCert.getPublicKey();

        try {
            // set cert values
            cert.setSerialNumber(certSerial);
            cert.setSubjectDN(orgCert.getSubjectDN());
            cert.setPublicKey(publicKey);
            cert.setIssuerDN(issuerCert.getSubjectDN());
            cert.setValidNotBefore(orgCert.getNotBefore());
            if (issuerCert.getNotAfter().after(orgCert.getNotAfter())) {
                cert.setValidNotAfter(orgCert.getNotAfter());
            } else {
                cert.setValidNotAfter(issuerCert.getNotAfter());
            }

            // Add other extensions
            if (extensions != null) {
                for (int i = 0; i < extensions.length; i++) {
                    cert.addExtension(extensions[i]);
                }
            }
            // Add AKI
            byte[] keyID = ((SubjectKeyIdentifier) issuerCert.getExtension(SubjectKeyIdentifier.oid)).get();
            cert.addExtension(new AuthorityKeyIdentifier(keyID));

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
}
