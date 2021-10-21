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
package com.aaasec.sigserv.cssigapp.data;

import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import com.aaasec.sigserv.cscommon.PEM;
import iaik.x509.X509Certificate;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;

/**
 * Database model for issued certificates
 */
public final class DbCert {

    public static final int REVOKED = 1, NOT_REVOKED = 0;
    private BigInteger serial;
    private String pemCert;
    private int revoked = 0;
    private long revDate = 0, issueDate = 0;
    private X509Certificate certificate;

    public DbCert() {
        serial = BigInteger.ZERO;
        pemCert = "";
        certificate = null;
    }

    public DbCert(String pemCert) {
        setPemCert(pemCert);
        if (certificate != null) {
            serial = certificate.getSerialNumber();
            issueDate = System.currentTimeMillis();
        } else {
            serial = BigInteger.ZERO;
        }
    }

    public DbCert(X509Certificate certificate) {
        setCertificate(certificate);
        if (certificate != null) {
            serial = certificate.getSerialNumber();
            issueDate = System.currentTimeMillis();
        } else {
            serial = BigInteger.ZERO;
        }
    }

    public long getIssueDate() {
        return issueDate;
    }

    public void setIssueDate(long issueDate) {
        this.issueDate = issueDate;
    }

    public String getPemCert() {
        return pemCert;
    }

    public void setPemCert(String pemCert) {
        this.pemCert = pemCert;
        certificate = CertificateUtils.getCertificate(pemCert);
    }

    public long getRevDate() {
        return revDate;
    }

    public void setRevDate(long revDate) {
        this.revDate = revDate;
    }

    public int getRevoked() {
        return revoked;
    }

    public void setRevoked(int revoked) {
        this.revoked = revoked;
    }

    public String getSerialStr() {
        return serial.toString();
    }

    public BigInteger getSerial() {
        return serial;
    }

    public void setSerial(String serialStr) {
        try {
            serial = new BigInteger(serialStr);
        } catch (Exception ex) {
            serial = BigInteger.ZERO;
        }
    }

    public void setSerial(BigInteger serial) {
        this.serial = serial;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
        try {
            pemCert = PEM.getPemCert(certificate.getEncoded());
        } catch (CertificateEncodingException ex) {
            certificate = null;
            pemCert = "";
        }
    }
}
