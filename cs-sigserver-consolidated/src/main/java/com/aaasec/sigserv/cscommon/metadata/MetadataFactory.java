/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cscommon.metadata;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.metadata.mdq.MdqMetadata;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author stefan
 */
public class MetadataFactory {

    private static final Logger LOG = Logger.getLogger(MetadataFactory.class.getName());
    private SourceType source = SourceType.File;
    private MetaData currentMetadata = null;
    private long lastRecache = 0;
    private String location=null, certLocation = null;
    private int recachetimeMinutes=60;

    public MetadataFactory() {
    }

    public MetaData getMetadata() {
        return getMetadata(false, false);
    }

    public void init() {
        getMetadata();
    }

    public MetaData getMetadata(boolean forceUpdate, boolean daemon) {
        LOG.fine("Getting current metadata - forceUpdate=" + forceUpdate + " - daemon=" + daemon);
        if (location==null){
            LOG.log(Level.SEVERE, null, new RuntimeException("No metadata location configured") );
            return null;
        }

        if (source == SourceType.MDQ) {
            // MDQ metadata has its own refresh mechanism and timer.
            LOG.fine("Returning MDQ metadata source");
            return currentMetadata;
        }

        // If requester is a daemon, then recache time applies. If you are not a daemon, wait until 2 recache times has passed to require update
        int multiplier = daemon ? 1 : 2;
        if (currentMetadata != null
          && System.currentTimeMillis() < getNextUpdate(recachetimeMinutes * multiplier)
          && forceUpdate == false) {
            LOG.fine("Returning cached metadata");
            return currentMetadata;
        }

        lastRecache = System.currentTimeMillis();

        if (certLocation == null) {
            LOG.fine("No metadata cert is configured. Attempting to get file stored local metadata");
            source = SourceType.File;
            MetaData newMetadata = new LoclFileMetaDataSource(new File(location), recachetimeMinutes);
            if (newMetadata.isInitialized()) {
                LOG.fine("Reloaded metadata from file: " + location);
                currentMetadata = newMetadata;
            }
            LOG.fine("Returning current file stored metadata from source: " + location);
            return currentMetadata;
        }

        X509Certificate cert;
        try {
            LOG.fine("Obtaining metadata certificate from " + certLocation);
            byte[] certBytes = FileOps.readBinaryFile(new File(certLocation));
            cert = getX509Cert(certBytes);
        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Unable to parse metadata certificate file " + certLocation, ex);
            return null;
        }

        if (location.endsWith("/entities/")) {
            LOG.fine("Metadata location is an MDQ location. Creating an MDQ metadata source");
            source = SourceType.MDQ;
            currentMetadata = new MdqMetadata(location, cert);
            return currentMetadata;
        }

        source = SourceType.URL;
        LOG.fine("Reloading metadata from URL source " + location);
        MetaData newMetadata = new UrlMetaDataSource(location, cert, recachetimeMinutes);
        if (newMetadata.isInitialized()) {
            LOG.info("Successfully reloaded metadata from URL source " + location);
            currentMetadata = newMetadata;
            return currentMetadata;
        }
        LOG.warning("Failure to download metadata from URL source " + location + ". Using old cached version");
        return currentMetadata;
    }

    private static X509Certificate getX509Cert(byte[] certData) {

        CertificateFactory cf;
        X509Certificate X509Cert;
        try {
            cf = CertificateFactory.getInstance("X.509");
            X509Cert = (java.security.cert.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certData));
            return X509Cert;
        } catch (Exception ex) {
            LOG.warning("Unable to parse Metadata validation certificate");
        }
        return null;
    }

    private long getNextUpdate(int recachetimeMinutes) {
        return lastRecache + (recachetimeMinutes * 1000 * 60);
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public void setCertLocation(String certLocation) {
        this.certLocation = certLocation;
    }

    public void setRecachetimeMinutes(int recachetimeMinutes) {
        this.recachetimeMinutes = recachetimeMinutes;
    }

    public enum SourceType {

        URL, File, MDQ
    }
}
