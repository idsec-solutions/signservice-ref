/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigserver.auth;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cscommon.data.AuthnStatus;
import com.aaasec.sigserv.cscommon.metadata.MetaData;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import com.aaasec.sigserv.cssigapp.data.DbSignTask;
import com.aaasec.sigserv.cssigapp.db.SignTaskTable;
import com.aaasec.sigserv.cssigapp.instances.InstanceConfig;
import com.aaasec.sigserv.cssigapp.models.RequestModel;
import com.aaasec.sigserv.cssigapp.models.SigServerModel;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import com.aaasec.sigserv.sigserver.RequestModelFactory;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.*;
import org.opensaml.xml.encryption.EncryptedKey;
import com.aaasec.sigserv.sigauthsp.models.KeyStoreBundle;
import com.aaasec.sigserv.sigauthsp.utils.ApCredential;
import com.aaasec.sigserv.sigauthsp.utils.ApResponseHandler;
import com.aaasec.sigserv.sigauthsp.utils.OsSigvalResult;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;

/**
 *
 * @author stefan
 */
public class SAMLResponseHandler {

    private static final Logger LOG = Logger.getLogger(SAMLResponseHandler.class.getName());
    private static final String RELAY_STATE_PARAM = "RelayState";
    private static final String RESPONSE_PARAM = "SAMLResponse";
    private SigServerModel model;
    private SignTaskTable signDb;

    public SAMLResponseHandler(SigServerModel model) {
        this.model = model;
        String sigTaskDir = FileOps.getfileNameString(model.getDataLocation(), "sigTasks");
        String sigTaskDbFile = FileOps.getfileNameString(sigTaskDir, "sigTasks.db");
        signDb = new SignTaskTable(sigTaskDbFile);
    }

    public RequestModel processResponse(HttpServletRequest request, HttpServletResponse response) {
        LOG.fine("Processing SAML authentication response");
        String relayState = request.getParameter(RELAY_STATE_PARAM);
        String b64SamlResponse = request.getParameter(RESPONSE_PARAM);
        ApResponseHandler respHandler = null;
        String id = "";
        String idpEntityId = null;
        AuthnStatus status = new AuthnStatus();

        try {
            Response samlResponse = ApResponseHandler.unmarshallB64Response(b64SamlResponse);
            id = RequestModelFactory.getResponseId(samlResponse.getInResponseTo());
            LOG.fine("SAML response in response to: " + id);
            String recipientEntityId = getRecipient(samlResponse, id);
            LOG.fine("Recipient entityId: "+ recipientEntityId);
            ApCredential spCred = getApCredentials(recipientEntityId);
            idpEntityId = samlResponse.getIssuer().getDOM().getTextContent();
            LOG.fine("IdP entityId: " + idpEntityId);
            MetaData metadata = ContextParameters.getMetadata();
            Map<String, List<String>> certMap = metadata.getCertMap();
            status = getAuthnStatus(samlResponse);
            LOG.fine("Found metadata for IdP: " + certMap.containsKey(idpEntityId));

            if (certMap.containsKey(idpEntityId)) {
                List<String> pemCerts = certMap.get(idpEntityId);
                LOG.fine("Found " + pemCerts.size() + " certificates in IdP metadata");
                for (String pemCert : pemCerts) {
                    X509Certificate idpCert = CertificateUtils.getCertificateFromPEM(pemCert);
                    LOG.fine("Found cert in IdP metadata issued to: " + idpCert.getSubjectX500Principal());
                    ApCredential idpCred = new ApCredential(idpCert.getEncoded());
                    respHandler = new ApResponseHandler(samlResponse, spCred, idpCred);
                    if (isSignatureVerified(respHandler)) {
                        LOG.fine("IdP certificate verifies the signature on the response - signature validation completed");
                        break;
                    }
                }
            }

            if (respHandler == null) {
                LOG.fine("Failure to verify SAML response from IdP");
                return getErrorReq(id, status, idpEntityId);
            }

        } catch (Exception ex) {
            LOG.warning("Parsing SAML response from IdP caused exception: " + ex.getMessage());
            return getErrorReq(id, status, idpEntityId);
        }

        LOG.fine("Found verified SAML authentication response. Now parsing user assertion...");

        RequestModelFactory rmf = new RequestModelFactory();
        RequestModel req = rmf.getRequestModel(respHandler);
        if (req == null) {
            LOG.warning("Failed to parse user identity information from SAML response");
            req = getErrorReq(id, status, idpEntityId);
        }

        LOG.fine("Successfully parsed SAML response from IdP");
        return req;
    }

    private AuthnStatus getAuthnStatus(Response samlResponse) {
        try {
            Status status = samlResponse.getStatus();
            StatusCode statusCode = status.getStatusCode();
            StatusMessage statusMessage = status.getStatusMessage();

            // Collect values
            String statusCodeStr = statusCode.getValue();
            String statusCodeChild = null;
            String statusMessageStr = null;
            if (statusCode.hasChildren()){
                statusCodeChild = statusCode.getStatusCode().getValue();
            }
            if (statusMessage != null){
                statusMessageStr = statusMessage.getMessage() != null ? statusMessage.getMessage() : "";
            }
            LOG.fine("Authentication status received: " + statusCodeStr + " " + statusMessageStr);
            return new AuthnStatus(statusCodeStr, statusCodeChild, statusMessageStr);

        } catch (Exception ex) {
            LOG.log(Level.SEVERE, "Failed to parse SAML status", ex);
            return new AuthnStatus();
        }
    }

    private boolean isSignatureVerified(ApResponseHandler respHandler) {
        OsSigvalResult responseSignatureValidation = respHandler.getResponseSignatureValidation();
        if (responseSignatureValidation.isSigned()) {
            LOG.fine("SAML response is signed");
            if (responseSignatureValidation.isValidSignature()) {
                LOG.fine("Response signature validation succeeded");
                return true;
            } else {
                LOG.warning("Response signature validation failed");
                return false;
            }
        }
        LOG.warning("SAML response is unsigned. Checking signature on assertion instead");
        OsSigvalResult assertionSignatureValidation = respHandler.getAssertionSignatureValidation();
        if (assertionSignatureValidation.isSigned()) {
            LOG.fine("SAML assertion is signed");
            if (assertionSignatureValidation.isValidSignature()) {
                LOG.fine("SAML assertion signature is valid");
                return true;
            } else {
                LOG.warning("SAML assertion signature validation failed");
                return false;
            }
        }
        LOG.warning("SAML response is unsigned and has unsigned assertion");
        return false;
    }

    private RequestModel getErrorReq(String id, AuthnStatus authnStatus, String idpEntityId) {
        RequestModel req = new RequestModel();
        req.setId(id);
        AuthData user = new AuthData(null,null,null,null, idpEntityId,null,null, new ArrayList<>());
        user .setAuthnStatus(authnStatus);
        req.setAuthData(user);
        return req;
    }

    private String getRecipient(Response samlResponse, String sigTaskId) {
        try {
            List<Assertion> assertions = samlResponse.getAssertions();
            List<EncryptedAssertion> encryptedAssertions = samlResponse.getEncryptedAssertions();

            if (assertions != null && assertions.size() > 0) {
                Assertion assertion = assertions.get(0);
                List<AudienceRestriction> audienceRestrictions = assertion.getConditions().getAudienceRestrictions();
                for (AudienceRestriction audRestr : audienceRestrictions) {
                    for (Audience aud : audRestr.getAudiences()) {
                        String audienceURI = aud.getAudienceURI();
                        String entityIdInstanceName = ContextParameters.getInstanceConf().getEntityIdInstanceName(audienceURI);
                        if (entityIdInstanceName != null) {
                            return audienceURI;
                        }
                    }
                }
            }

            if (encryptedAssertions != null && encryptedAssertions.size() > 0) {
                EncryptedAssertion encAssert = encryptedAssertions.get(0);
                List<EncryptedKey> encryptedKeys = encAssert.getEncryptedData().getKeyInfo().getEncryptedKeys();
                for (EncryptedKey encKey : encryptedKeys) {
                    String recipient = encKey.getRecipient();
                    String entityIdInstanceName = ContextParameters.getInstanceConf().getEntityIdInstanceName(recipient);
                    if (entityIdInstanceName != null) {
                        return recipient;
                    }
                }
            }

            //Failed to obtain recipient entityID from encrypted assertion. Trying the sign task DB
            DbSignTask signTask = signDb.getDbRecord(sigTaskId);
            if (signTask == null || signTask.getServiced() > 0) {
                return null;
            }
            byte[] requestBytes = signTask.getRequest();
            SignRequestDocument sigReqDoc = null;
            try {
                sigReqDoc = SignRequestDocument.Factory.parse(new ByteArrayInputStream(requestBytes));
                String recipient = sigReqDoc.getSignRequest().getOptionalInputs().getSignRequestExtension().getSignService().getStringValue();
                return recipient;
            } catch (Exception ex) {
            }

        } catch (Exception e) {
        }
        return null;
    }

    private ApCredential getApCredentials(String recipientEntityId) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (recipientEntityId == null) {
            return null;
        }
        InstanceConfig instanceConf = ContextParameters.getInstanceConf();
        String instanceName = instanceConf.getEntityIdInstanceName(recipientEntityId);
        KeyStore keyStore = instanceConf.getInstanceKeyStoreMap().get(instanceName).getKeyStore();
        char[] passw = instanceConf.getInstanceMap().get(instanceName).getKeyStorePass().toCharArray();
        ApCredential spCred = new ApCredential(new KeyStoreBundle(keyStore, passw));
        return spCred;
    }

}
