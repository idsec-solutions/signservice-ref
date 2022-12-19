/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigserver.auth;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.enums.SSOBinding;
import com.aaasec.sigserv.cscommon.metadata.MetaData;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import com.aaasec.sigserv.cssigapp.data.DbSignTask;
import com.aaasec.sigserv.cssigapp.data.ReqResult;
import com.aaasec.sigserv.cssigapp.instances.InstanceConfig;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.aaasec.sigserv.cssigapp.sap.SAPHandler;
import org.opensaml.saml2.core.Attribute;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageDocument;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageType;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignRequestExtensionType;
import se.elegnamnden.id.csig.x11.sap.ns.SADRequestDocument;
import com.aaasec.sigserv.sigauthsp.SAMLAuthHandler;
import com.aaasec.sigserv.sigauthsp.models.AuthReqData;
import com.aaasec.sigserv.sigauthsp.models.AuthReqResult;
import com.aaasec.sigserv.sigauthsp.models.KeyStoreBundle;
import com.aaasec.sigserv.sigauthsp.models.RequestType;
import se.swedenconnect.id.authn.x10.principalSelection.ns.MatchValueType;
import se.swedenconnect.id.authn.x10.principalSelection.ns.PrincipalSelectionDocument;
import se.swedenconnect.id.authn.x10.principalSelection.ns.PrincipalSelectionType;
import x0Assertion.oasisNamesTcSAML2.AttributeStatementType;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;

/**
 *
 * @author stefan
 */
public class AuthRequest implements Constants {

    private static final Logger LOG = Logger.getLogger(AuthRequest.class.getName());
    private boolean error = false;
    private String errorMessage = "Authn request not initialized";
    private final DbSignTask task;
    private final ReqResult signRequestStatus;
    private final byte[] sigReqBytes;
    private AuthReqResult samlRequest;
    private KeyStore instanceKeyStore;
    private char[] instanceKeyStorePass;
    private String sigServiceEntityId;
    private String sadRequestId;
    private static final Random RNG = new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8));

    public AuthRequest(DbSignTask task, ReqResult signRequestStatus, byte[] sigReqBytes, String sigServiceEntityId) {
        this.task = task;
        this.signRequestStatus = signRequestStatus;
        this.sigReqBytes = sigReqBytes;
        this.sigServiceEntityId = sigServiceEntityId;
        InstanceConfig instanceConf = ContextParameters.getInstanceConf();
        String instanceName = instanceConf.getEntityIdInstanceName(sigServiceEntityId);
        instanceKeyStore = instanceConf.getInstanceKeyStoreMap().get(instanceName).getKeyStore();
        instanceKeyStorePass = instanceConf.getInstanceMap().get(instanceName).getKeyStorePass().toCharArray();
    }

    public boolean isError() {
        return error;
    }

    public AuthReqResult getSamlRequest() {
        return samlRequest;
    }

    public KeyStore getInstanceKeyStore() {
        return instanceKeyStore;
    }

    public char[] getInstanceKeyStorePass() {
        return instanceKeyStorePass;
    }

    public String getSadRequestId() {
        return sadRequestId;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Prepares an authentication request to IdP
     * @return true if authentication request was successfully prepared.
     */
    public boolean prepareAuthRequest() {
        try {
            SignRequestDocument sigReqDoc = SignRequestDocument.Factory.parse(new ByteArrayInputStream(sigReqBytes));
            SignRequestExtensionType signRequestExtension = sigReqDoc.getSignRequest().getOptionalInputs().getSignRequestExtension();
            SignMessageType signMessage = signRequestExtension.getSignMessage();
            SignMessageDocument signMessageDoc = null;
            if (signMessage != null) {
                signMessageDoc = SignMessageDocument.Factory.newInstance();
                signMessageDoc.setSignMessage(signMessage);
            }

            AuthReqData reqData = new AuthReqData();
            reqData.setId(signRequestStatus.id);
            reqData.setSignMessage(signMessageDoc);
            reqData.setSadRequest(ContextParameters.getSapHandler().getSadRequest(sigReqDoc));
            reqData.setForceAuthn(true);
            reqData.setIdpEntityId(getIdPEntityId(sigReqDoc));
            reqData.setKsBundle(new KeyStoreBundle(instanceKeyStore, instanceKeyStorePass));
            reqData.setLoa(getLoa(sigReqDoc, reqData.getIdpEntityId()));
            setReqUrlAndType(reqData, sigReqDoc);
            reqData.setSpEntityId(sigServiceEntityId);
            reqData.setPersistentId(false);

            setPrincipalSelection(reqData, signRequestExtension.getSigner());

            sadRequestId = getSadREequestId(reqData.getSadRequest());

            //Check if an error has bee detected so far. If so abort before attempting to generate request
            if (error == true) {
                return false;
            }

            samlRequest = SAMLAuthHandler.getRequest(reqData);
            samlRequest.setAuthReqData(reqData);

            if (samlRequest == null || samlRequest.getLoginData() == null){
                error = true;
                errorMessage = "Failed to generate authentication request";
            }

        } catch (Exception ex) {
            error = true;
            errorMessage = "Auth request preparation exception: " + ex.getMessage();
            Logger.getLogger(AuthRequest.class.getName()).warning(errorMessage);
        }

        return !error;
    }

  private void setPrincipalSelection(AuthReqData reqData, AttributeStatementType signer) {
    if (ContextParameters.getConf().getServiceType().equalsIgnoreCase("swamid-default")){
      LOG.info("using SWAMID profile. Ignore principal selection");
      return;
    }

    AttributeType[] attributeArray = signer.getAttributeArray();
    if (attributeArray == null || attributeArray.length ==0){
        return;
    }

    try {
        PrincipalSelectionDocument psDocument = PrincipalSelectionDocument.Factory.newInstance();
        PrincipalSelectionType principalSelection = psDocument.addNewPrincipalSelection();
        for (AttributeType attr: attributeArray){
            String name = attr.getName();
            String value = SAPHandler.getAttrVal(attr.getAttributeValueArray(0));
            String nameFormat = attr.getNameFormat();
            MatchValueType matchValue = principalSelection.addNewMatchValue();
            matchValue.setName(name);
            matchValue.setStringValue(value);
            if (nameFormat != null && !nameFormat.equalsIgnoreCase(Attribute.URI_REFERENCE))
                matchValue.setNameFormat(nameFormat);
        }
        reqData.setPrincipalSelection(psDocument);
    } catch (Exception ex){
        LOG.warning("Error parsing signer from SignRequest");
        return;
    }
  }

  private String getSadREequestId(SADRequestDocument sadRequest) {
        try {
            return sadRequest.getSADRequest().getID();
        } catch (Exception ex){
            return null;
        }
    }

    private String getIdPEntityId(SignRequestDocument sigReqDoc) {
        try {
            return sigReqDoc.getSignRequest().getOptionalInputs().getSignRequestExtension().getIdentityProvider().getStringValue();
        } catch (Exception ex) {
            error = true;
            errorMessage = "No valid IdP specified in request";
            return null;
        }
    }

    private List<String> getLoa(SignRequestDocument sigReqDoc, String idPEntityId) {
        if (idPEntityId == null){
            error = true;
            errorMessage = "No selected IdP";
            LOG.warning("No selected IdP at Loa selection process");
            return null;
        }
        if (ContextParameters.getConf().getServiceType().equalsIgnoreCase("swamid-default")){
            LOG.warning("using SWAMID profile. Ignore LoA requesting");
            return null;
        }
        List<String> idpSupportedClassRefList = ContextParameters.getMetadata().getIdpSupportedClassRefs(idPEntityId);
        if (idpSupportedClassRefList == null){
            error = true;
            errorMessage = "Requested IdP do not support any Auth context";
            return null;
        }
        boolean mustShow = false;
        List<String> requestContextClassRefList;
        try {
            SignRequestExtensionType signRequestExtension = sigReqDoc.getSignRequest().getOptionalInputs().getSignRequestExtension();
            SignMessageType signMessage = signRequestExtension.getSignMessage();
            if (signMessage != null) {
                mustShow = signMessage.getMustShow();
            }
            List<String> authnContextClassRefList = Arrays.asList(signRequestExtension.getCertRequestProperties().getAuthnContextClassRefArray());

            /*
               Implementing new signmessage loa strategy
               Test if IdP belongs to exception whitelist. If not, the sign service will request the requested LoA level, if supported by the IdP.
             */
            List<String> legacyLoaIdPs = ContextParameters.getConf().getLegacyLoaIdPs();
            if (legacyLoaIdPs != null && legacyLoaIdPs.contains(idPEntityId)){
                // This is a legacy IdP. Perform legacy conversion to signmessage URI
                boolean finalMustShow = mustShow;
                requestContextClassRefList = authnContextClassRefList.stream()
                  .map(authnContextClassRef -> LevelOfAssucance.getRequestContextClassRef(authnContextClassRef, signMessage != null,
                    finalMustShow, idpSupportedClassRefList, LevelOfAssucance.loa3))
                  .collect(Collectors.toList());
            } else {
                // Perform new request LoA assignment (Not using legacy signmessage URI:s
                requestContextClassRefList = idpSupportedClassRefList.stream()
                  .filter(idpLoa -> authnContextClassRefList.contains(idpLoa))
                  .collect(Collectors.toList());
                //requestContextClassRefList = idpSupportedClassRefList.contains(authnContextClassRefList) ? authnContextClassRefList : null;
            }

        } catch (Exception ex) {
            requestContextClassRefList =  Arrays.asList(LevelOfAssucance.getRequestContextClassRef(null, false, false, idpSupportedClassRefList, LevelOfAssucance.loa3));
        }

        if (requestContextClassRefList == null){
            error = true;
            errorMessage = "IdP does not support the required AuthnContextClassRef";
        }
        return requestContextClassRefList;
    }

    private void setReqUrlAndType(AuthReqData reqData, SignRequestDocument sigReqDoc) {
        MetaData metadata = ContextParameters.getMetadata();
        String idpEntityId = reqData.getIdpEntityId();
        Map<String, String> idpSsoMap = metadata.getSSOMap(idpEntityId);
        if (idpSsoMap == null) {
            error = true;
            errorMessage = "No valid IdP specified in request";
            return;
        }
        if (idpEntityId == null) {
            error = true;
            errorMessage = "No valid IdP specified in request";
            return;
        }
        if (ContextParameters.getConf().getServiceType().equalsIgnoreCase("swamid-default")){
            if (idpSsoMap.containsKey(SSOBinding.redirect.getBindginURI())) {
                reqData.setReqUrl(idpSsoMap.get(SSOBinding.redirect.getBindginURI()));
                reqData.setType(RequestType.unsignedRedirect);
                return;
            }
            if (idpSsoMap.containsKey(SSOBinding.post.getBindginURI())) {
                reqData.setReqUrl(idpSsoMap.get(SSOBinding.post.getBindginURI()));
                reqData.setType(RequestType.unsignedPost);
                return;
            }
        }
        if (idpSsoMap.containsKey(SSOBinding.post.getBindginURI())) {
            reqData.setReqUrl(idpSsoMap.get(SSOBinding.post.getBindginURI()));
            reqData.setType(RequestType.signedPost);
            return;
        }
        if (idpSsoMap.containsKey(SSOBinding.redirect.getBindginURI())) {
            reqData.setReqUrl(idpSsoMap.get(SSOBinding.redirect.getBindginURI()));
            reqData.setType(RequestType.signedRedirect);
            return;
        }
        error = true;
        errorMessage = "Specified IdP does not support POST or Redirect binding";
    }

    /**
     * Sends authentication request to IdP.
     * @param request HTTPServletRequest
     * @param response HTTPServletResponse
     */
    public void sendRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (error || samlRequest == null){
            response.getWriter().write(errorMessage);
            return;
        }

        AuthReqData authReqData = samlRequest.getAuthReqData();

        switch (authReqData.getType()) {
            case signedPost:
            case unsignedPost:
                response.setContentType("text/html;charset=UTF-8");
                response.getWriter().write(samlRequest.getLoginData());
                response.getWriter().close();
                break;
            case signedRedirect:
            case unsignedRedirect:
                response.sendRedirect(samlRequest.getLoginData());
        }

    }

}
