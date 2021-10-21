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

import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.CharConstants;
import com.aaasec.sigserv.cscommon.PEM;
import com.aaasec.sigserv.sigserver.auth.SAMLResponseHandler;
import iaik.x509.V3Extension;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.qualified.QCStatements;
import iaik.x509.extensions.qualified.structures.QCStatement;
import iaik.x509.extensions.qualified.structures.etsi.QcEuCompliance;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Certificate utils.
 */
public class CertificateUtils implements CharConstants {

    private static final Logger LOG = Logger.getLogger(CertificateUtils.class.getName());

    public static X509Certificate getCertificate(String pemCert) {
        if (pemCert == null) {
            return null;
        }
        return (getIaikCert(Base64Coder.decodeLines(PEM.trimPemCert(pemCert))));
    }

    public static iaik.x509.X509Certificate getIaikCert(byte[] certBytes) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "IAIK");
            X509Certificate iaikCert = (iaik.x509.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            return iaikCert;
        } catch (Exception ex) {
            String reson = ex.getMessage();
        }
        return null;
    }

    public static X509Certificate getCertificate(byte[] certData) {

        try {
//            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "IAIK");
            try {
                X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(
                        certData));
                return certificate;
            } catch (CertificateException e) {
                System.err.println("X509 Parsing Error");
                return null;
                //throw new RuntimeException("X509 error: "+ e.getMessage(), e);
            }
        } catch (Exception ex) {
            LOG.warning(ex.getMessage());
        }
        return null;
    }

    public static short getSdiType(java.security.cert.X509Certificate javaCert) {
        try {
            X509Certificate cert = getCertificate(javaCert.getEncoded());
            if (cert != null) {
                return getSdiType(cert);
            }
        } catch (CertificateEncodingException ex) {
        }
        return 4;
    }

    public static short getSdiType(X509Certificate cert) {
        boolean qualified = false;
        boolean rootCert = false;
        boolean eeCert = false;

        // CA test
        if (cert.getBasicConstraints() == -1) {
            eeCert = true;
        }

        // root test
        if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
            rootCert = true;
        }

        // qc test
        Enumeration<V3Extension> e = cert.listExtensions();
        if (e != null) {

            List<V3Extension> extList = new ArrayList<V3Extension>();
            while (e.hasMoreElements()) {
                extList.add(e.nextElement());
            }

            for (V3Extension rawExt : extList) {
                //QcStatements
                if (rawExt.getObjectID().equals(QCStatements.oid)) {
                    QCStatements qc = (QCStatements) rawExt;
                    // set property
                    QCStatement[] qCStatements = qc.getQCStatements();
                    for (QCStatement statement : qCStatements) {
                        if (statement.getStatementID().equals(QcEuCompliance.statementID)) {
                            qualified = true;
                        }
                    }
                }
            }
        }

        // return result
        short type = 0;
        if (!eeCert) {
            type = 1;
        }
        if (rootCert) {
            type = 2;
        }
        if (qualified) {
            type += 3;
        }
        return type;
    }

    public static String getSki(X509Certificate cert) {

        byte[] skiBytes = cert.getExtensionValue("2.5.29.14");
        if (null != skiBytes) {
            String rawSkiData = getHex(skiBytes);
            if (rawSkiData.length() > 8) {
                return (rawSkiData.substring(8, rawSkiData.length()));
            } else {
                return "hash";
            }
        }
        return "hash";
    }

    public static String getHex(byte[] inpBytes) {
        StringBuilder b = new StringBuilder();
        for (byte val : inpBytes) {
            int a = (int) val & 255;
            String hex = Integer.toHexString(a);
            if (hex.length() == 1) {
                hex = "0" + hex;
            }
            b.append(hex);
        }
        return b.toString();

    }

    /**
     * Get distinguished name component from X500 distinguished name
     *
     * @param distinguishedName The X500Principal holding the distinguished name
     * @param keyWord           Keyword for the target name component (e.g. "CN" for the
     *                          common name component)
     * @return The target name compnent (null if name component was not present)
     */
    public static String getNameComponent(X500Principal distinguishedName, String keyWord) {

        String dNameText = distinguishedName.getName();
        int startIndex = 0;
        int endIndex = 0;
        int c;
        boolean done = false;
        String nameComponent = null;
        String testWord = keyWord + "=";

        //Check if dn starts with keyword
        if (testWord.length() < dNameText.length()) {
            if (dNameText.substring(0, testWord.length()).equals(testWord)) {
                startIndex = testWord.length();
            }
        }

        for (int i = 0; i < dNameText.length(); i++) {
            c = (int) dNameText.charAt(i);

            switch (c) {
                case COMMA:
                    if (i + 1 + testWord.length() < dNameText.length()) {
                        if (dNameText.substring(i + 1, i + 1 + testWord.length()).equals(testWord)) {
                            startIndex = i + 1 + testWord.length();
                        }
                    }

                    if (startIndex > 0 && i > startIndex && !done) { // If CN is being parsed
                        endIndex = i;
                    }
                    break;
                case PLUS:
                    if (i + 1 + testWord.length() < dNameText.length()) {
                        if (dNameText.substring(i + 1, i + 1 + testWord.length()).equals(testWord)) {
                            startIndex = i + 1 + testWord.length();
                        }
                    }
                    if (startIndex > 0 && i > startIndex && !done) { // If CN is being parsed
                        endIndex = i;
                    }
                    break;
                case EQUAL:
                    if (startIndex > 0 && endIndex > startIndex) {
                        done = true;
                        nameComponent = dNameText.substring(startIndex, endIndex).trim();
                    }
            }
        }
        if (startIndex > 0 && !done) { // if CN was found but no end was detected in the loop
            nameComponent = dNameText.substring(startIndex, dNameText.length()).trim();
        }

        return nameComponent;
    }

    public static List<String> getLines(String inpString) {
        List lines = new LinkedList<String>();
        InputStream in = new ByteArrayInputStream(inpString.getBytes());
        Reader rdr = new InputStreamReader(in);
        BufferedReader input = new BufferedReader(rdr);

        try {
            try {
                String line = null;
                while ((line = input.readLine()) != null) {
                    lines.add(line);
                }
            } finally {
                input.close();
            }
        } catch (IOException ex) {
            LOG.warning(ex.getMessage());
        }
        return lines;
    }

    private static int getEndIndex(String line, String matchString) {
        int endIndex = -1;
        if (matchString.length() > line.length()) {
            return -1;
        }
        for (int i = 0; i < line.length(); i++) {
            if (i + matchString.length() < line.length() + 1) {
                if (line.substring(i, i + matchString.length()).equals(matchString)) {
                    endIndex = i + matchString.length();
                }
            }
        }
        return endIndex;
    }

    private static int getExtEndIndex(String line, String matchString) {
        int endIndex = -1;
        if (matchString.length() > line.length()) {
            return -1;
        }
        for (int i = 0; i < line.length(); i++) {
            if (i + matchString.length() < line.length()) {
                if (line.substring(i, i + matchString.length()).equals(matchString)) {
                    for (int j = i + i + matchString.length(); j < line.length(); j++) {
                        int c = (int) line.charAt(j);
                        if (c == COLON) {
                            endIndex = j + 1;
                            break;
                        }
                    }
                }
            }
        }
        return endIndex;
    }

    public static java.security.cert.X509Certificate getCertificateFromPEM(String pemCert) {
        byte[] certBytes = Base64Coder.decodeLines(PEM.trimPemCert(pemCert));

        java.security.cert.X509Certificate cert = null;
        InputStream inStream = new ByteArrayInputStream(certBytes);
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (java.security.cert.X509Certificate) cf.generateCertificate(inStream);
        } catch (CertificateException ex) {
            Logger.getLogger(SAMLResponseHandler.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            if (inStream != null) {
                try {
                    inStream.close();
                } catch (IOException ex) {
                    Logger.getLogger(CertificateUtils.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        return cert;
    }

}
