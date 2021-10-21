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
package com.aaasec.sigserv.cssigapp.utils;

import iaik.x509.X509Certificate;
import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

/**
 * Certificate conversions.
 */
public class KsCertFactory {

    private static java.security.cert.CertificateFactory cf;
    private static java.security.cert.Certificate cert;
    private static java.security.cert.CRL crl;
    private static java.security.cert.X509Certificate X509Cert;
    private static iaik.x509.X509Certificate iaikCert;

    public static java.security.cert.Certificate getCertificate(iaik.x509.X509Certificate iaikCert) {
        try {
            cf = CertificateFactory.getInstance("X.509");
            cert = cf.generateCertificate(new ByteArrayInputStream(iaikCert.getEncoded()));
            return cert;
        } catch (CertificateException ex) {
        }
        return null;
    }

    public static java.security.cert.Certificate getCertificate(byte[] certBytes) {
        try {
            cf = CertificateFactory.getInstance("X.509");
            cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
            return cert;
        } catch (CertificateException ex) {
        }
        return null;
    }

    public static iaik.x509.X509Certificate getIaikCert(java.security.cert.Certificate inCert) {
        try {
            cf = CertificateFactory.getInstance("X.509", "IAIK");
            iaik.x509.X509Certificate iaikCert = (iaik.x509.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(inCert.getEncoded()));
            return iaikCert;
        } catch (Exception ex) {
        }
        return null;
    }

    public static iaik.x509.X509Certificate getIaikCert(byte[] certBytes) {
        try {
            cf = CertificateFactory.getInstance("X.509", "IAIK");
            iaikCert = (iaik.x509.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            return iaikCert;
        } catch (Exception ex) {
        }
        return null;
    }

    public static java.security.cert.X509Certificate getX509Cert(byte[] certData) {

        try {
            cf = CertificateFactory.getInstance("X.509");
            try {
                X509Cert = (java.security.cert.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certData));
                return X509Cert;
            } catch (CertificateException e) {
                return null;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static java.security.cert.CRL convertCRL(iaik.x509.X509CRL iaikCRL) {
        try {
            cf = CertificateFactory.getInstance("X.509");
            crl = cf.generateCRL(new ByteArrayInputStream(iaikCRL.getEncoded()));
            return crl;
        } catch (Exception ex) {
        }
        return null;

    }

    public static iaik.x509.X509CRL getCRL(byte[] crlBytes) {
        try {
            cf = CertificateFactory.getInstance("X.509", "IAIK");
            iaik.x509.X509CRL crl = (iaik.x509.X509CRL) cf.generateCRL(new ByteArrayInputStream(crlBytes));
            return crl;
        } catch (Exception ex) {
        }
        return null;

    }

    public static List<X509Certificate> getIaikCertList(Certificate[] pdfSignCerts) {
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        for (Certificate javaCert:pdfSignCerts){
            try {
                X509Certificate cert = getIaikCert(javaCert.getEncoded());
                certList.add(cert);
            } catch (CertificateEncodingException ex) {
            }
        }
        return certList;
    }
}
