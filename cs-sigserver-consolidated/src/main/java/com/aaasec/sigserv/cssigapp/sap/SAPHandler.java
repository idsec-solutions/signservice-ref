package com.aaasec.sigserv.cssigapp.sap;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cscommon.enums.ContextAttributes;
import com.aaasec.sigserv.cscommon.enums.SamlAttribute;
import com.aaasec.sigserv.cscommon.metadata.EntityAttributeVal;
import com.aaasec.sigserv.cscommon.metadata.MetaData;
import com.aaasec.sigserv.cscommon.metadata.MetaDataDoc;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import com.aaasec.sigserv.sigserver.auth.LevelOfAssucance;
import com.google.gson.Gson;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;
import org.apache.xmlbeans.impl.values.XmlAnyTypeImpl;
import se.elegnamnden.id.csig.x11.dssExt.ns.CertRequestPropertiesType;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageType;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignRequestExtensionType;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignTaskDataType;
import se.elegnamnden.id.csig.x11.sap.ns.SADRequestDocument;
import se.elegnamnden.id.csig.x11.sap.ns.SADRequestType;
import se.svelegtest.id.csig.x11.csspsupport.CertType;
import x0Assertion.oasisNamesTcSAML2.AssertionDocument;
import x0Assertion.oasisNamesTcSAML2.AttributeStatementType;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class SAPHandler implements Constants {
    private static final Logger LOG = Logger.getLogger(SAPHandler.class.getName());
    private static final Random RNG = new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8));
    private static String SAD_EXT_ID = "seElnSadext";
    private static final Gson GSON = new Gson();


    public SAPHandler() {
    }

    public SADRequestDocument getSadRequest(SignRequestDocument sigReqDoc) {
        String idPEntityId = getIdPEntityId(sigReqDoc.getSignRequest());
        if (idPEntityId == null) {
            return null;
        }

        boolean isSignMessageRequested = isSignMessageRequested(sigReqDoc.getSignRequest());
        boolean idPSAPEnabled = isIdPSAPEnabled(idPEntityId);
        boolean sapRequired = isSADRequired(sigReqDoc.getSignRequest());

        if ((idPSAPEnabled || sapRequired) && isSignMessageRequested) {
            return getSadRequestDocument(sigReqDoc);
        }

        return null;
    }

    private boolean isSignMessageRequested(SignRequestDocument.SignRequest signRequest) {
        try {
            SignMessageType signMessage = signRequest.getOptionalInputs().getSignRequestExtension().getSignMessage();
            if (signMessage != null) {
                return true;
            }
        } catch (Exception ex) {
        }
        return false;
    }

    public boolean isSADRequired(SignRequestDocument.SignRequest signRequest) {
        try {
            CertRequestPropertiesType.CertType.Enum certType = signRequest.getOptionalInputs().getSignRequestExtension().getCertRequestProperties().getCertType();
            return certType.equals(CertType.QC_SSCD) || certType.toString().toUpperCase().endsWith("SSCD");
        } catch (Exception ex) {
            LOG.warning("Unexpected error when parsing sign request in SAD Request generation process: " + ex.getMessage());
            return false;
        }
    }

    public boolean isIdPSAPEnabled(String idPEntityId) {
        MetaData metaData = ContextParameters.getMetadata();
        EntityDescriptorType idpEd = metaData.getEntityDescriptor(idPEntityId);
        if (idpEd == null) {
            return false;
        }
        Map<String, List<EntityAttributeVal>> entityAttributes = MetaDataDoc.getEntityAttributes(idpEd);

        if (entityAttributes.containsKey(ENTITY_CATEGORY)) {
            Optional<EntityAttributeVal> scal2Prop = entityAttributes.get(ENTITY_CATEGORY).stream()
                    .filter(entityAttributeVal -> entityAttributeVal.value.equalsIgnoreCase(SCAL2_SERVICE_PROPERTY))
                    .findFirst();
            return scal2Prop.isPresent();
        }

        return false;
    }

    private SADRequestDocument getSadRequestDocument(SignRequestDocument sigReqDoc) {
        String requestID;
        String signatureServiceEntityId;
        int docCount = 0;

        try {
            SignRequestDocument.SignRequest signRequest = sigReqDoc.getSignRequest();
            signatureServiceEntityId = signRequest.getOptionalInputs().getSignRequestExtension().getSignService().getStringValue();
            requestID = signRequest.getRequestID();
            docCount = signRequest.getInputDocuments().getOtherArray(0).getSignTasks().getSignTaskDataArray().length;
        } catch (Exception ex) {
            LOG.warning("Unexpected error when parsing sign request in SAD Request generation process: " + ex.getMessage());
            return null;
        }

        SADRequestDocument sadRequestDocument = SADRequestDocument.Factory.newInstance();
        SADRequestType sadRequest = sadRequestDocument.addNewSADRequest();
        sadRequest.setID("_" + new BigInteger(128, RNG).toString(16));
        sadRequest.setRequesterID(signatureServiceEntityId);
        // Optionally setting requested version.
        sadRequest.setRequestedVersion("1.0");
        if (requestID == null || docCount < 1) {
            LOG.warning("No Request ID or no documents to sing in SAD Request generation process");
            return null;
        }
        sadRequest.setSignRequestID(requestID);
        sadRequest.setDocCount(docCount);

        return sadRequestDocument;
    }

    private String getIdPEntityId(SignRequestDocument.SignRequest sigReq) {
        try {
            return sigReq.getOptionalInputs().getSignRequestExtension().getIdentityProvider().getStringValue();
        } catch (Exception ex) {
            return null;
        }
    }

    public void verifySAP(AuthData user, SignRequestDocument.SignRequest sigReq, String sapRequestId) throws RuntimeException {
        try {
            String idPEntityId = getIdPEntityId(sigReq);
            Optional<String> sadOptional = user.getAttribute().stream()
                    .filter(valueList -> valueList.get(0).equalsIgnoreCase(SamlAttribute.sad.name()))
                    .map(valueList -> valueList.get(2))
                    .findFirst();

            final boolean idPSAPEnabled = isIdPSAPEnabled(idPEntityId);
            final boolean sadRequired = isSADRequired(sigReq);
            final boolean isSignMessageRequested = isSignMessageRequested(sigReq);

            if (sadRequired && !sadOptional.isPresent()) {
                throw new IllegalArgumentException("A SAD is required for this signature but no SAD was provided by IdP");
            }
            if (idPSAPEnabled && !sadOptional.isPresent() && isSignMessageRequested) {
                throw new IllegalArgumentException("IdP is enabled for SAP but failed to return a requested SAD");
            }

            if (!sadOptional.isPresent()) {
                //No SAD is required, but this is OK
                LOG.info("No SAD was provided by IdP, but none was required to complete signature");
                return;
            }

            SignedJWT signedJWT = SignedJWT.parse(sadOptional.get());

            List<PublicKey> idpPubkeyList = ContextParameters.getMetadata().getCertificates(idPEntityId).stream()
                    .map(s -> CertificateUtils.getCertificateFromPEM(s).getPublicKey())
                    .collect(Collectors.toList());

            boolean sigValid = idpPubkeyList.stream()
                    .filter(publicKey -> publicKey instanceof RSAPublicKey)
                    .map(publicKey -> (RSAPublicKey) publicKey)
                    .filter(rsaPublicKey -> {
                        JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);
                        try {
                            if (signedJWT.verify(verifier)) {
                                return new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime());
                            }
                            return false;
                        } catch (Exception e) {
                            return false;
                        }
                    })
                    .findFirst()
                    .isPresent();

            if (!sigValid) {
                throw new IllegalArgumentException("SAD Signature fails validation");
            }
            // Retrieve / verify the JWT claims according to the app requirements
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            String sadJson = signedJWT.getJWTClaimsSet().getClaim(SAD_EXT_ID).toString();
            SadExtData sadExtData = GSON.fromJson(sadJson, SadExtData.class);

            // Finally - verify the claims
            verifySADClaims(claims, sadExtData, sigReq, sapRequestId, user);

        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Error while validating SAD - " + ex.getMessage());
        }
    }

    private void verifySADClaims(JWTClaimsSet claims, SadExtData sadExtData, SignRequestDocument.SignRequest sigReq, String sadRequestId, AuthData user) throws Exception {
        SignRequestExtensionType signRequestExtension = sigReq.getOptionalInputs().getSignRequestExtension();
        SignTaskDataType[] signTaskDataArray = sigReq.getInputDocuments().getOtherArray(0).getSignTasks().getSignTaskDataArray();
        AttributeType subjAttribute = signRequestExtension.getSigner().getAttributeArray(0);
        String attrName = subjAttribute.getName();
        String subjName = getAttrVal(subjAttribute.getAttributeValueArray(0));

        String signServiceEntityID = signRequestExtension.getSignService().getStringValue();
        String idpEntityId = signRequestExtension.getIdentityProvider().getStringValue();
        List<String> reqAuthnContextClassRefList = Arrays.asList(signRequestExtension.getCertRequestProperties().getAuthnContextClassRefArray());

        String authnContextClassRef = user.getContext().stream()
                .filter(valList -> valList.get(0).equalsIgnoreCase(ContextAttributes.authContextClass.getAttrName()))
                .map(valList -> valList.get(2))
                .findFirst().get();

        String sigReqRequestID = sigReq.getRequestID();
        int docCount = signTaskDataArray.length;


        // Verify subject
        if (!attrName.equalsIgnoreCase(sadExtData.getAttr())) {
            LOG.fine("SAD subject specifies different attribute than SignRequest. This is not typical but is not an error.");
            // Check that SAD attribute is among the authenticated attributes
            try{
                AssertionDocument assertioinDocument = user.getAssertioinDocument(0);
                AttributeStatementType attributeStatement = assertioinDocument.getAssertion().getAttributeStatementArray(0);
                Optional<AttributeType> sadAttrFromAssert = Arrays.stream(attributeStatement.getAttributeArray())
                  .filter(attribute -> attribute.getName().equalsIgnoreCase(sadExtData.getAttr()))
                  .findFirst();
                if (!sadAttrFromAssert.isPresent()){
                    throw new IllegalAccessException("Identity Attribute in SAD is not asserted by IdP");
                }
                String attrVal = getAttrVal(sadAttrFromAssert.get().getAttributeValueArray(0));
                if (!attrVal.equalsIgnoreCase(claims.getSubject())){
                    throw new IllegalAccessException("Identity Attribute value in SAD is not asserted by IdP");
                }
            } catch (Exception ex){
                throw new IllegalAccessException("Error validating SAD subject identity attribute");
            }
        } else {
            // Same attribute as singer in SignRequest and SAD subject. Make sure id values match
            if (!subjName.equalsIgnoreCase(claims.getSubject())) {
                throw new IllegalAccessException("Wrong Signer Identity data in SAD");
            }
        }

        // Verify Audience
        if (!signServiceEntityID.equalsIgnoreCase(claims.getAudience().get(0))) {
            throw new IllegalAccessException("Wrong signature service ID in SAD");
        }

        // Verify Issuer
        if (!idpEntityId.equalsIgnoreCase(claims.getIssuer())) {
            throw new IllegalAccessException("Wrong SAD issuer (IdP)");
        }

        // Verify issued at time
        if (!new Date(System.currentTimeMillis() + 60000).after(claims.getIssueTime())) {
            throw new IllegalAccessException("SAD Issue time after current time");
        }

        // Verify Unique identifier is present
        String jwtid = claims.getJWTID();
        if (jwtid == null || jwtid.isEmpty()) {
            throw new IllegalAccessException("SAD has no ID");
        }

        // Verify Version
        String ver = sadExtData.getVer();
        if (ver != null) {
            if (!ver.equalsIgnoreCase("1.0")) {
                throw new IllegalAccessException("Unrecognized SAD version");
            }
        }

        if (!sadExtData.getIrt().equalsIgnoreCase(sadRequestId)) {
            throw new IllegalAccessException("SAD request ID does not match in response to parameter in SAD");
        }

        // Verify LoA
        /*
          If IdP is on exception list for legacy signmessage LoA, then perform old checks. Otherwise check that the signmessage hash attribute is present
         */
        List<String> legacyLoaIdPs = ContextParameters.getConf().getLegacyLoaIdPs();
        if (legacyLoaIdPs != null && legacyLoaIdPs.contains(idpEntityId)){
            // This is a Legacy IdP peform old Signmessage loa test
            Optional<LevelOfAssucance> reqLoAOptional = Arrays.stream(LevelOfAssucance.values())
              .filter(levelOfAssucance ->
                levelOfAssucance.getSigMessContextClassRef() != null &&
                  (reqAuthnContextClassRefList.contains(levelOfAssucance.getContextClassRef())
                    || reqAuthnContextClassRefList.contains(levelOfAssucance.getSigMessContextClassRef())))
              .findFirst();
            if (!reqLoAOptional.isPresent()) {
                throw new IllegalAccessException("Unsupported requested LoA");
            }
            if (!reqLoAOptional.get().getSigMessContextClassRef().equalsIgnoreCase(authnContextClassRef)) {
                throw new IllegalAccessException("Asserted LoA is not Sign Message LoA compatible with the request");
            }
        } else {
            // Perform test according to new LoA comparison requirements
            if (authnContextClassRef == null || !reqAuthnContextClassRefList.contains(authnContextClassRef)){
                throw new IllegalAccessException("Asserted LoA is not compatible with the requested LoA");
            }
        }


        // Verify Request ID
        if (!sadExtData.getReqid().equalsIgnoreCase(sigReqRequestID)) {
            throw new IllegalAccessException("Unrecognized Sign request ID");
        }

        // Verify document count
        if (docCount != sadExtData.getDocs()) {
            throw new IllegalAccessException("Unrecognized Sign request ID");
        }

    }

    public static String getAttrVal(XmlObject attrVal) {
        if (attrVal instanceof XmlString) {
            return ((XmlString) attrVal).getStringValue();
        }
        if (attrVal instanceof XmlAnyTypeImpl) {
            return ((XmlAnyTypeImpl) attrVal).getStringValue();
        }
        return null;
    }
}
