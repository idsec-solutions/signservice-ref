package com.aaasec.sigserv.cscommon.metadata.mdq;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.w3c.dom.Document;

import com.aaasec.lib.crypto.xml.SigVerifyResult;
import com.aaasec.lib.crypto.xml.XMLSign;
import com.aaasec.sigserv.cscommon.DerefUrl;
import com.aaasec.sigserv.cscommon.URIComponentCoder;

import x0Metadata.oasisNamesTcSAML2.EntityDescriptorDocument;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class EntityDescriptorMdDoc {

  private final static Logger LOG = Logger.getLogger(EntityDescriptorMdDoc.class.getName());
  private EntityDescriptorDocument metadataDoc;
  private boolean valid;
  private SigVerifyResult sigVerifyResult;
  private boolean sigPkMatch;
  private boolean signatureVerified;
  private X509Certificate verifyCert;

  public EntityDescriptorMdDoc(String url, X509Certificate verifyCert, String entityId) {
    this.verifyCert = verifyCert;
    String mdqUrl = url + URIComponentCoder.encodeURIComponent(entityId);

    try {
      byte[] mdBytes = DerefUrl.getBytes(mdqUrl, DerefUrl.SslSecurityPolicy.SYSTEM_DEF);
      metadataDoc = EntityDescriptorDocument.Factory.parse(new ByteArrayInputStream(mdBytes));
      LOG.fine("Downloaded metadata record. Verifying signature");
      verifySignature(mdBytes);
      this.valid = signatureVerified && sigPkMatch;
    }
    catch (Exception ex) {
      LOG.warning("Unable to download and parse metadata for " + entityId + ". Exception: " + ex);
    }
  }

  private void verifySignature(byte[] metadataBytes) {
    try {
      sigVerifyResult = XMLSign.verifySignature(metadataBytes);
      signatureVerified = sigVerifyResult.valid;
      if (signatureVerified) {
        LOG.fine("Signature validation success");
        sigPkMatch = checkPkMatch();
      } else {
        LOG.fine("Signature verification failed");
      }
    }
    catch (Exception ex) {
      LOG.warning("MD Signature verification falied" + ex);
    }
  }

  private boolean checkPkMatch() {
    if (verifyCert == null || sigVerifyResult == null || sigVerifyResult.cert == null) {
      return false;
    }
    X509Certificate sigCert = sigVerifyResult.cert;
    if (sigCert.getPublicKey().equals(verifyCert.getPublicKey())) {
      LOG.fine("Signature key match");
      return true;
    }
    LOG.fine("Signature key match failed");
    return false;
  }

  public EntityDescriptorDocument getMetadataDoc() {
    return metadataDoc;
  }

  public boolean isValid() {
    return valid;
  }
}
