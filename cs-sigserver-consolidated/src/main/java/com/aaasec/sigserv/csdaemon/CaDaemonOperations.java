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
package com.aaasec.sigserv.csdaemon;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.PEM;
import com.aaasec.sigserv.csdaemon.ca.RootCertificationAuthority;
import com.aaasec.sigserv.cssigapp.ca.CertPath;
import com.aaasec.sigserv.cssigapp.ca.CertificationAuthority;
import iaik.x509.X509Certificate;
import java.io.File;
import java.security.cert.CertificateEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Operations performed by the CA Daemon application.
 */
public class CaDaemonOperations {

    private static final Logger LOG = Logger.getLogger(CaDaemonOperations.class.getName());
    private final DaemonModel model;

    /**
     * Constructor
     *
     * @param model Daemon model data
     */
    public CaDaemonOperations(DaemonModel model) {
        this.model = model;
    }

    public void doDaemonTask() {
        // Get caDirectories and base data
        LOG.info("Starting timed CA and Metadata re-cache maintenance");
        LOG.fine("Sign service daemon: checking metadata re-cache");
        ContextParameters.getMetadataFactory().getMetadata(false, true);
        LOG.fine("Sign service daemon: Issuing CA certificates fom root...");
        // Root CA actions
        issueCAcerts();
        LOG.fine("Sign service daemon: Creating CRLs...");
        // Revocation
        revokeCerts();
        // Publish data
        LOG.fine("Sign service daemon: Publishing data...");
        publishCaData();
        LOG.fine("Sign service daemon: CA maintenance completed");
    }

    private void revokeCerts() {
        for (CertificationAuthority ca : model.getCaList()) {
            int cnt = ca.revokeCertificates();
            LOG.fine("Sign service daemon: Revoked " + String.valueOf(cnt) + " certs from " + ca.getCaName());
        }
    }

    private void publishCaData() {
        for (CertificationAuthority ca : model.getCaList()) {
            File exportCrlFile = ca.getExportCrlFile();
            File crlFile = ca.getCrlFile();
            if (crlFile.canRead()) {
                FileOps.createDir(exportCrlFile.getParentFile().getAbsolutePath());
                FileOps.saveByteFile(FileOps.readBinaryFile(crlFile), exportCrlFile);
                LOG.fine("Sign service daemon: Exported " + exportCrlFile.getAbsolutePath());
            }
        }
    }

    private void issueCAcerts() {
        RootCertificationAuthority rootCa = model.getRootCa();
        for (CertificationAuthority ca : model.getCaList()) {
            //Ignore the root
            if (!ca.equals(rootCa)) {
                CertPath certPath = ca.getCertPath();
                if (certPath == null) {
                    X509Certificate xCert = rootCa.issueXCert(ca.getSelfSignedCert());
                    certPath = new CertPath();
                    try {
                        certPath.add(PEM.getPemCert(xCert.getEncoded()));
                        certPath.add(PEM.getPemCert(rootCa.getSelfSignedCert().getEncoded()));
                        ca.setCertPath(certPath);
                        LOG.info("Sign service daemon: CA cert issued for " + ca.getCaName());
                    } catch (CertificateEncodingException ex) {
                        Logger.getLogger(CaDaemonOperations.class.getName()).log(Level.SEVERE, null, ex);
                    }

                }
            }
        }
    }
}
