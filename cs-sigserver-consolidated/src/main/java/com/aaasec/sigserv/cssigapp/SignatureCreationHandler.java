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
package com.aaasec.sigserv.cssigapp;

import com.aaasec.lib.crypto.xml.SignedXmlDoc;
import com.aaasec.lib.crypto.xml.XMLSign;
import com.aaasec.lib.crypto.xml.xades.XAdESObject;
import com.aaasec.sigserv.cscommon.Constants;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.XhtmlForm;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cscommon.data.AuthnStatus;
import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.cscommon.enums.Enums.SCResponseCodeMinor;
import com.aaasec.sigserv.cscommon.enums.Enums.ResponseCodeMajor;
import com.aaasec.sigserv.cscommon.enums.SigTaskStatus;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.testdata.TestData;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import com.aaasec.sigserv.cssigapp.ca.CAFactory;
import com.aaasec.sigserv.cssigapp.ca.CertificationAuthority;
import com.aaasec.sigserv.cssigapp.centralsig.CentralSigning;
import com.aaasec.sigserv.cssigapp.centralsig.DigestAlgorithm;
import com.aaasec.sigserv.cssigapp.centralsig.SupportedSigAlgoritm;
import com.aaasec.sigserv.cssigapp.data.DbSignTask;
import com.aaasec.sigserv.cssigapp.data.SigConfig;
import com.aaasec.sigserv.cssigapp.db.SignTaskTable;
import com.aaasec.sigserv.cssigapp.instances.InstanceConfig;
import com.aaasec.sigserv.cssigapp.models.ResponseSigDataModel;
import com.aaasec.sigserv.cssigapp.models.SigServerModel;
import com.aaasec.sigserv.cssigapp.sap.SAPHandler;
import com.aaasec.sigserv.cssigapp.utils.ASN1Util;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import com.aaasec.sigserv.cssigapp.utils.NamedKeyStore;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Node;
import se.elegnamnden.id.csig.x11.dssExt.ns.*;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignTaskDataType.AdESType;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignTaskDataType.SigType;
import se.idsec.audit.signservice.AuditLogger;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0Assertion.oasisNamesTcSAML2.ConditionsType;
import x0CoreSchema.oasisNamesTcDss1.Base64SignatureDocument;
import x0CoreSchema.oasisNamesTcDss1.Eid2RespAnyType;
import x0CoreSchema.oasisNamesTcDss1.InternationalStringType;
import x0CoreSchema.oasisNamesTcDss1.ResultDocument.Result;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument.SignRequest;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument.SignResponse;

/**
 * Signature creation handler.
 */
public class SignatureCreationHandler implements Constants {

    private static final Logger LOG = Logger.getLogger(SignatureCreationHandler.class.getName());
    private static final String URN_PREFIX = "urn:oid:";
    private SigServerModel model;
    private String caDir, caMainDir;
    private CertificationAuthority ca;
    private CAFactory caFactory = new CAFactory();
    private KeyStoreFactory ksFactory;
    private SignTaskTable signDb;

    public SignatureCreationHandler(SigServerModel model) {
        this.model = model;
        ksFactory = new KeyStoreFactory(model);
        ksFactory.cleanup();
        ksFactory.stackUp();
        caMainDir = FileOps.getfileNameString(model.getDataLocation(), "CA");
        String sigTaskDir = FileOps.getfileNameString(model.getDataLocation(), "sigTasks");
        String sigTaskDbFile = FileOps.getfileNameString(sigTaskDir, "sigTasks.db");
        signDb = new SignTaskTable(sigTaskDbFile);
        getCA();
    }

    private void getCA() {
        SigConfig conf = model.reloadConf();
        caDir = FileOps.getfileNameString(caMainDir, conf.getSignatureCaName());
        ca = new CertificationAuthority(conf.getSignatureCaName(), caDir, model, ContextParameters.getConf().getCaKsPassword().toCharArray(), ContextParameters.getConf().getCaKsAlias());
        if (!ca.isInitialized()) {
            caFactory.createCa(ca);
        }
    }

    public String createSignature(String sigTaskId, AuthData user) {

        //Check if sigTask is serviced
        DbSignTask signTask = signDb.getDbRecord(sigTaskId);
        if (signTask == null || signTask.getServiced() > 0) {
            return "Signature service error - Signing task is missing or has already ben serviced";
        }

        signTask.setServiced(System.currentTimeMillis());
        signDb.addOrReplaceRecord(signTask);

        // Process task
        RequestAndResponse reqRes = getSignatureResponse(sigTaskId, user);
        SignResponseDocument responseDoc = reqRes.getReponseDoc();
        String sigServiceEntityId = reqRes.getRequest().getOptionalInputs().getSignRequestExtension().getSignService().getStringValue();
        InstanceConfig instanceConf = ContextParameters.getInstanceConf();
        String sigInstanceName = instanceConf.getEntityIdInstanceName(sigServiceEntityId);
        NamedKeyStore instKs = instanceConf.getInstanceKeyStoreMap().get(sigInstanceName);
        AuditLogger.logSignResult(reqRes, sigInstanceName);

        //Sign response
        try {
            String responseUrl = getResponseUrl(reqRes.getRequest());
            LOG.info("Generating response to response URL: " + responseUrl);

            String nonce = reqRes.getRequest().getRequestID();
            Node sigParent = getResponseSignatureParent(responseDoc);
            byte[] unsignedXml = XmlBeansUtil.getStyledBytes(responseDoc);
            SignedXmlDoc signedXML = XMLSign.getSignedXML(unsignedXml, instKs.getPrivate(), instKs.getKsCert(), sigParent, true, false);
            byte[] signedResponse = signedXML.sigDocBytes;
            String xhtml = XhtmlForm.getSignXhtmlForm(XhtmlForm.Type.SIG_RESPONSE_FORM, responseUrl, signedResponse, nonce);

            //Store testdata
            TestData.storeXhtmlResponse(nonce, xhtml);
            TestData.storeResponse(nonce, signedResponse);

            return xhtml;
        } catch (Exception ex) {
            AuditLogger.log("Critical error while attempting to generate user signature: {}", ex.getMessage());
            LOG.log(Level.SEVERE, "Critical error while attempting to generate user signature", ex);
        }
        return "Signature service error - Unable to service the request";
    }

    public RequestAndResponse getSignatureResponse(String sigTaskId, AuthData user) {
        RequestAndResponse reqRes = new RequestAndResponse();

        ksFactory.stackUp();
        DbSignTask signTask = signDb.getDbRecord(sigTaskId);
        if (signTask == null) {
            LOG.warning("NO sign task in signTask DB matching this request");
            reqRes.setReponseDoc(getErrorResponse(null, null, ResponseCodeMajor.SigCreationError, "No matching request"));
            return reqRes;
        }
        LOG.fine("Found sign task from DB");
        byte[] requestBytes = signTask.getRequest();
        SignRequestDocument sigReqDoc = null;
        SignRequest sigReq = null;
        SignRequestExtensionType eid2Req = null;
        String idpEntityId = null;
        try {
            sigReqDoc = SignRequestDocument.Factory.parse(new ByteArrayInputStream(requestBytes));
            sigReq = sigReqDoc.getSignRequest();
            eid2Req = sigReq.getOptionalInputs().getSignRequestExtension();
            idpEntityId = eid2Req.getIdentityProvider().getStringValue();
        } catch (Exception ex) {
            LOG.warning("Error parsing sign request for this signing operation: " + ex.getMessage());
            reqRes.setReponseDoc(getErrorResponse(null, null, ResponseCodeMajor.InsufficientInfo));
            return reqRes;
        }
        if (eid2Req == null) {
            LOG.warning("No EID2 sign request extension in sign request");
            reqRes.setReponseDoc(getErrorResponse(null, null, ResponseCodeMajor.InsufficientInfo));
            return reqRes;
        }
        LOG.fine("Extracted all vital elements from SignRequest");
        reqRes.setRequestDoc(sigReqDoc);
        byte[] encSigReq = requestBytes;

        //Check if user was authenticated
        if (user == null || user.getId() == null) {
            LOG.warning("Failed to authenticate user. Signature generation aborted");
            AuthnStatus authnStatus = user.getAuthnStatus();
            String message = authnStatus.getStatusMessage() == null ? "Signer authentication failed or was cancelled by user" : "Signer authentication failed: " + authnStatus.getStatusMessage();
            SCResponseCodeMinor responseCodeMinor = (authnStatus.getChildStatusCode() != null && authnStatus.getChildStatusCode().equalsIgnoreCase("http://id.elegnamnden.se/status/1.0/cancel"))?
              SCResponseCodeMinor.userCancel:
              SCResponseCodeMinor.absent;
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, responseCodeMinor, message));
            return reqRes;
        }
        LOG.fine("Found authenticated user");

        // Check the validity and appropriate inclusion of a SAP in the authentication response.
        try {
            ContextParameters.getSapHandler().verifySAP(user, sigReq, signTask.getPageInfo().sadRequestId);
        } catch (RuntimeException ex) {
            LOG.warning("Failed to verify SAP: " + ex.getMessage());
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, ex.getMessage()));
            return reqRes;
        }
        LOG.fine("Passed SAP verification (successful or obsolete)");
        // Check that signMessageDigest is present if required
        /*
          Here is a legacy behavior dependent of whether the IdP is on the signmessage legacy list or not
        */
        List<String> legacyLoaIdPs = ContextParameters.getConf().getLegacyLoaIdPs();
        if (legacyLoaIdPs == null || !legacyLoaIdPs.contains(idpEntityId)){
            LOG.fine("Performing sign message and sign message digest checks");
            // This is not a legacy IdP. check for signMessage digest
            SignMessageType signMessage = eid2Req.getSignMessage();
            if (signMessage != null && signMessage.isSetMustShow()) {
                try {
                    AttributeType[] attributeArray = user.getUserAssertion().getAttributeStatement().getAttributeArray();
                    Optional<AttributeType> smDigestOptional = Arrays.stream(attributeArray)
                      .filter(attributeType -> attributeType.getName().equals("urn:oid:1.2.752.201.3.14"))
                      .filter(attributeType -> attributeType.getAttributeValueArray() != null
                        && attributeType.getAttributeValueArray().length == 1)
                      .findFirst();
                    if (!smDigestOptional.isPresent()){
                        LOG.warning("Sign Message Digest is required, but not present");
                        reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, "Sign message was required but signMessageDigest attribute is missing from IdP"));
                        return reqRes;
                    }
                    XmlObject attributeValue = smDigestOptional.get().getAttributeValueArray(0);
                    String attrValStr = SAPHandler.getAttrVal(attributeValue);
                    String[] smDigestFrag = attrValStr.split(";");
                    DigestAlgorithm smDigestAlgo = DigestAlgorithm.getDigestAlgoFromURI(smDigestFrag[0]);
                    byte[] decode = Base64.decode(smDigestFrag[1]);
                    if (decode.length ==0 || decode.length != smDigestAlgo.gethLen()){
                        LOG.warning("Sign message digest attribute has invalid data");
                        reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, "Sign message was required but signMessageDigest attribute has invalid content"));
                        return reqRes;
                    }
                } catch (Exception ex){
                    LOG.log(Level.SEVERE, "Critical error while checking sign message and sign message digest", ex);
                    reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, "Sign message was required but signMessageDigest attribute has invalid content"));
                    return reqRes;
                }
            }
        } else {
            LOG.fine("This is a legacy IdP excluded from sign message digest checks");
        }

        // Check if the same user has started another sign task before completing this one.
        if (signTask.getStatus().equals(SigTaskStatus.DuplicateUserReq)) {
            LOG.fine("Multiple current active sign tasks for the same user. Aborting signing");
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, "A second request was received for the specified signer before this request was serviced"));
            return reqRes;
        }
        // Update status
        signTask.setStatus(SigTaskStatus.Serviced);
        signDb.addOrReplaceRecord(signTask);

        boolean userMatch = checkUserID(eid2Req, user);
        if (!userMatch) {
            LOG.warning("User mismatch. The authenticated user does not match the requested signer");
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.BadRequest, SCResponseCodeMinor.userMismatch ,"Authenticated user does not match the requested signer"));
            return reqRes;
        }
        LOG.fine("User match. The authenticated user matches the intended signer");

        boolean authnContextMatch = checkAuthnContext(eid2Req, user);
        if (!authnContextMatch) {
            LOG.warning("LoA mismatch. The authenticated LoA does not match the requested LoA");
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.BadRequest, SCResponseCodeMinor.userMismatch ,"Requested LoA does not match the Assertion LoA"));
            return reqRes;
        }
        LOG.fine("LoA match. The authenticated LoA matches the requested LoA");

        ConditionsType conditions = eid2Req.getConditions();
        boolean inValidityTime = getTimeValidity(conditions);
        if (!inValidityTime) {
            LOG.warning("Sign request is not within its validity time");
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.BadRequest, SCResponseCodeMinor.epired , "Request has expired"));
            return reqRes;
        }

        Map<String, ResponseSigDataModel> signatures = new HashMap<String, ResponseSigDataModel>();
        String reqSigAlgoURI = null;
        //SigAlgorithms sigAlgo = null;
        SupportedSigAlgoritm sigAlgo = null;
        SignTaskDataType[] sigInfoInpArray = new SignTaskDataType[]{};
        KeyPair kp = null;
        X509Certificate[] chain = null;
        try {
            reqSigAlgoURI = eid2Req.getRequestedSignatureAlgorithm();
            sigAlgo = SupportedSigAlgoritm.getAlgoFromXmlName(reqSigAlgoURI);
            if (sigAlgo == null) {
                LOG.warning("The requested signature algorithm is not supported");
                reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, "Unsupported requested algorithm"));
                LOG.warning("Signature creation aborted. Requested signature algoritm" + reqSigAlgoURI + " is not supported");
                return reqRes;
            }
            sigInfoInpArray = sigReq.getInputDocuments().getOtherArray(0).getSignTasks().getSignTaskDataArray();
            kp = ksFactory.getKeyPair(sigAlgo, sigReq.getRequestID());

            //Issue signing cert
            LOG.fine("Issuing signer certificate");

            // For swamid services, set the SP entityID as the authenticating service to allow SP identification in the user cert
            String spServiceId = null;  // A null value means that the default value from instance config is used.
            String serviceType = ContextParameters.getConf().getServiceType();
            if (serviceType != null && serviceType.equalsIgnoreCase("swamid-default")){
                // Set the SP entityID as the service name
                spServiceId = eid2Req.getSignRequester().getStringValue();
            }
            X509Certificate userCert = ca.issueUserCert(user, kp.getPublic(), eid2Req.getCertRequestProperties(), spServiceId);

            //Store cert TestData
            TestData.storeUserCert(sigReq.getRequestID(), userCert.getEncoded());

            if (userCert == null) {
                reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, "Failed to issue signer certificate"));
                LOG.warning("Certificate issuance prohibited due to unsatisfied attribute requirements");
                return reqRes;
            }
            chain = ca.getChain(userCert);
        } catch (Exception ex) {
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError, "Failed to issue signer certificate"));
            LOG.log(Level.SEVERE, "Critical error while generating user certificate" , ex.getMessage());
            return reqRes;
        }

        try {
            LOG.fine("Attempting to generate the signature data");
            //Get requested sig algo
            //Check CMS signed attributes
            for (int i = 0; i < sigInfoInpArray.length; i++) {
                SignTaskDataType sigInfoInp = sigInfoInpArray[i];
                byte[] tDataBytes = sigInfoInp.getToBeSignedBytes();
                SigType.Enum sigType = sigInfoInp.getSigType();
                AdESType.Enum adESType = sigInfoInp.getAdESType();
                String docName = sigInfoInp.getSignTaskId();
                docName = docName == null ? "##NULL##" : docName;
                ResponseSigDataModel respSigData = new ResponseSigDataModel();

                if (sigType == SigType.CMS || sigType == SigType.PDF) {
                    LOG.fine("PDF/CMS signature generation");
                    boolean pades = adESType.equals(AdESType.BES) || adESType.equals(AdESType.EPES);
                    LOG.fine("PAdES signature: "+pades);

                    //Check signing time
                    Date cmsSigningTime = ASN1Util.getCmsSigningTime(tDataBytes);

                    // Check if cms signing time is present. If present, then check that the value is reasonable.
                    if (cmsSigningTime != null) {
                        // If signingTime attribute is present and request is PAdES, then this is an error.
                        // signingTime is forbidden in PAdES signatures.
                        if (pades) {
                            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError));
                            return reqRes;
                        }
                        //For non PAdES Signatures, check that the value at least is within tolerances
                        long claimedTime = cmsSigningTime.getTime();
                        long currentTime = System.currentTimeMillis();
                        if (claimedTime < (currentTime - MAX_SIG_TIME_TOLERANCE) || claimedTime > currentTime + MAX_SIG_TIME_TOLERANCE) {
                            LOG.warning("Signing time mismatch. To large difference between current time and signing time");
                            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError));
                            return reqRes;
                        }
                    }

                    //Add or replace CMSAlgoProtection
                    if (pades){
                        if (ContextParameters.getConf().isPadesCmsAlgoProtection()){
                            // Only add CMS algo protection to PAdES if permitted by configuration
                            tDataBytes = CentralSigning.updateOrAddCMSAlgoProtectionAndSigTIme(tDataBytes, sigAlgo);
                        }
                    } else {
                        tDataBytes = CentralSigning.updateOrAddCMSAlgoProtectionAndSigTIme(tDataBytes, sigAlgo);
                    }

                    //Add an ESSSigningCertificate signed attribute if such attribute was present in the request or the signature is a PAdES signature
                    tDataBytes = CentralSigning.updateESSSignCertAttribute(tDataBytes, chain[0], sigAlgo.getDigestAlgo(), false, pades);
                    respSigData.setAdesSig(pades);
                }
                respSigData.setTbsBytes(tDataBytes);

                //If doctype is XML. Check if requested signature is of XAdES type
                String sigId = null;
                byte[] adesObjBytes;
                XAdESObject xobj;
                if (sigType == SigType.XML && (adESType == AdESType.BES || adESType == AdESType.EPES)) {
                    LOG.fine("XML Signature generation");
                    AdESObjectType adESObject = sigInfoInp.getAdESObject();
                    if (adESObject != null) {
                        sigId = adESObject.getSignatureId();
                    }
                    if (sigId != null) {
                        adesObjBytes = adESObject.getAdESObjectBytes();
                        xobj = new XAdESObject(tDataBytes, adesObjBytes, sigId);
                        xobj.setCertRef(chain[0], sigAlgo.getDigestAlgo().getXmlId(), true);
                        xobj.updateXadesSignedInfo(sigAlgo.getDigestAlgo().getXmlId());
                        byte[] updatedXadesSignedInfo = xobj.getCanonicalSignedInfoBytes();
                        adesObjBytes = xobj.getCanonicalObjectBytes();
                        respSigData.setAdesSig(true);
                        respSigData.setSignatureId(sigId);
                        respSigData.setAdesObjBytes(adesObjBytes);

                        //Get caconocal Signed info bytes
                        XmlObject sigInfoXmlObj = XmlObject.Factory.parse(new ByteArrayInputStream(updatedXadesSignedInfo));
                        byte[] canonicalTbsBytes = XmlBeansUtil.getCanonicalBytes(sigInfoXmlObj);
                        tDataBytes = XAdESObject.getCanonicalXml(XmlObject.Factory.parse(new ByteArrayInputStream(canonicalTbsBytes)).getDomNode());

                        // debug
                        //String newTDataBytesStr = new String(tDataBytes, Charset.forName("UTF-8"));

                        respSigData.setTbsBytes(tDataBytes);

                    } else {
                        reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError , "Failed to generate XAdES signature - No Signature Id provided"));
                        LOG.warning("Missing Signature Id in XAdES request - Signing aborted");
                        return reqRes;
                    }
                }

                byte[] signature = CentralSigning.centralSign(sigAlgo, tDataBytes, kp.getPrivate(), sigType);
                respSigData.setSignature(signature);
                signatures.put(docName, respSigData);
            }

//            byte[] signature = XMLSign.rsaSign(tbsData, ksObjects.getPk());
            try {
                reqRes.setReponseDoc(generateSignResponse(encSigReq, sigReq, user, chain, signatures, sigAlgo.getXmlName()));
            } catch (Exception ex) {
                LOG.log(Level.SEVERE, "Critical error while attempting to generate signature" , ex);
                reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError));
            }

        } catch (Exception ex) {
            reqRes.setReponseDoc(getErrorResponse(encSigReq, sigReq, ResponseCodeMajor.SigCreationError));
            LOG.log(Level.SEVERE, "Critical error while attempting to generate signature" , ex);
        }
        return reqRes;
    }

    private boolean checkAuthnContext(SignRequestExtensionType eid2Req, AuthData user) {
        try {
            List<String> requestedLoaList = Arrays.asList(eid2Req.getCertRequestProperties().getAuthnContextClassRefArray());
            List<String> authnLoaList = user.getAuthnLoaList();
            for (String assertionLoA : authnLoaList){
                if (requestedLoaList.contains(assertionLoA)){
                    LOG.fine("LoA match: " + assertionLoA + "is requested and declared in the assertion");
                    return true;
                }
            }
            LOG.warning("LoA mismatch. Requested LoAs: " + String.join(",", requestedLoaList) + " Assertion LoA: " + String.join("," + authnLoaList));
            return false;
        } catch (Exception ex){
            LOG.warning("Error processing LoA information - " + ex.getMessage());
            return false;
        }
    }

    private boolean checkUserID(SignRequestExtensionType sigReq, AuthData user) {
        boolean match = true;
        AttributeType[] signerAttrs;
        try {
            signerAttrs = sigReq.getSigner().getAttributeArray();
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "Unable to obtain requested ID attributes from sign request", ex);
            return false;
        }

        List<List<String>> idpAttributes = user.getAttribute();
        if (idpAttributes == null || idpAttributes.isEmpty()) {
            LOG.warning("No attributes are available for the authenticated user in the response from the IdP");
            return false;
        }
        for (AttributeType signerAttr : signerAttrs) {
            String attrId = signerAttr.getName();
            String attrVal;
            XmlObject[] aa = signerAttr.getAttributeValueArray();
            if (aa[0] instanceof XmlString) {
                attrVal = ((XmlString) aa[0]).getStringValue();
            } else {
                LOG.warning("Requested signer attribute " + attrId + "has no value to match");
                return false;
            }
            // check if attribute is provided by idp
            boolean attrMatch = false;
            for (List<String> valueList : idpAttributes) {
                String attrName = valueList.get(0);
                if (Enums.idAttributes.containsKey(attrName)) {
                    if (Enums.idAttributes.get(attrName).equals(stripOid(attrId))) {
                        if (valueList.get(2).equals(attrVal)) {
                            attrMatch = true;
                            break;
                        } else {
                            LOG.warning("Requested signer attribute " + attrId + " value mismatch. Expected: " + attrVal + " - Found: " + valueList.get(2));
                        }
                    }
                }
            }
            if (!attrMatch) {
                LOG.warning("Requested signer attribute " + attrId + " value matching failed");
                match = false;
                break;
            }
        }
        LOG.fine(match ? "User attribute matching succeeded" : "User attribute matching failed");
        return match;
    }

    private static String stripOid(String oid) {
        String norm = (oid.startsWith("urn:oid:")) ? oid.substring(8) : oid;
        return norm;

    }

    private static boolean compareOidStrings(String oid1, String oid2) {
        String norm1 = stripOid(oid1);
        String norm2 = stripOid(oid2);
        return norm1.equalsIgnoreCase(norm2);
    }

    private String stripUrn(String typeId) {
        if (typeId.startsWith(URN_PREFIX)) {
            return typeId.substring(URN_PREFIX.length());
        }
        return typeId;
    }

    private SignResponseDocument generateSignResponse(byte[] encSigReq, SignRequest sigReq,
                                                      AuthData user, X509Certificate[] chain, Map<String, ResponseSigDataModel> signatures, String sigAlgo) throws Exception {
        SignRequestExtensionType eid2Req = sigReq.getOptionalInputs().getSignRequestExtension();
        SignResponseDocument responseDoc = SignResponseDocument.Factory.newInstance();
        SignResponse response = responseDoc.addNewSignResponse();
        SignResponseExtensionType eid2Response = response.addNewOptionalOutputs().addNewSignResponseExtension();
        eid2Response.setVersion(getProtocolVersion(sigReq));

        Result result = response.addNewResult();
        InternationalStringType resultMessage = result.addNewResultMessage();
        resultMessage.setLang("en");
        resultMessage.setStringValue(Enums.ResponseCodeMajor.Success.getMessage());
        result.setResultMajor(Enums.ResponseCodeMajor.Success.getCode());

        CertificateChainType certChainType = eid2Response.addNewSignatureCertificateChain();
        for (X509Certificate cert : chain) {
            certChainType.addNewX509Certificate().setByteArrayValue(cert.getEncoded());
        }
        // Add signature result
        try {
            SignTaskDataType[] signatureTaskDataArray = sigReq.getInputDocuments().getOtherArray(0).getSignTasks().getSignTaskDataArray();
            List<SignTaskDataType> newSigTasks = new ArrayList<SignTaskDataType>();
            int sigCount = signatureTaskDataArray.length;

            for (int i = 0; i < sigCount; i++) {
                SignTaskDataType signatureTaskData = signatureTaskDataArray[i];
                SignTaskDataType respSigTaskData = (SignTaskDataType) signatureTaskData.copy();
//            SignTaskDataType respSigTaskData = SignTaskDataType.Factory.parse(signatureTaskData.getDomNode());
                Base64SignatureType b64Signature = respSigTaskData.addNewBase64Signature();
                String sigTaskId = signatureTaskData.getSignTaskId();
                sigTaskId = sigTaskId == null ? "##NULL##" : sigTaskId;
                b64Signature.setByteArrayValue(signatures.get(sigTaskId).getSignature());
                b64Signature.setType(sigAlgo);
                updateAdesData(respSigTaskData, signatures.get(sigTaskId));
                newSigTasks.add(respSigTaskData);
            }

            response.addNewSignatureObject().addNewOther().addNewSignTasks().setSignTaskDataArray(newSigTasks.toArray(new SignTaskDataType[newSigTasks.size()]));
        } catch (Exception ex) {
            // If no signature task object was present in the request
            if (signatures.containsKey("##NULL##")) {
                Base64SignatureDocument.Base64Signature base64Signature = response.addNewSignatureObject().addNewBase64Signature();
                base64Signature.setByteArrayValue(signatures.get("##NULL##").getSignature());
                base64Signature.setType(sigAlgo);
            }
        }

        response.setProfile(sigReq.getProfile());
        response.setRequestID(sigReq.getRequestID());
        eid2Response.setResponseTime(Calendar.getInstance());
        eid2Response.setRequest(encSigReq);
        eid2Response.setSignerAssertionInfo(user.getUserAssertion());
        SignerAssertionInfoType signerAssertionInfo = eid2Response.getSignerAssertionInfo();
        List<byte[]> assertions = user.getAssertions();
        if (!assertions.isEmpty()) {

            //Store Assertion in TestData
            TestData.storeAssertions(sigReq.getRequestID(), assertions);

            SAMLAssertionsType SamlAssertions = signerAssertionInfo.addNewSamlAssertions();
            byte[][] assertionArray = assertions.toArray(new byte[][]{});
            SamlAssertions.setAssertionArray(assertionArray);
        }

        return responseDoc;
    }

    private void updateAdesData(SignTaskDataType respSigTaskData, ResponseSigDataModel respSigData) {
        respSigTaskData.setToBeSignedBytes(respSigData.getTbsBytes());
        if (respSigData.getAdesObjBytes() == null) {
            return;
        }
        AdESObjectType adESObject = respSigTaskData.getAdESObject();
        if (adESObject == null) {
            adESObject = respSigTaskData.addNewAdESObject();
        }
        adESObject.setAdESObjectBytes(respSigData.getAdesObjBytes());
        adESObject.setSignatureId(respSigData.getSignatureId());
    }

    private SignResponseDocument getErrorResponse(byte[] encSigReq, SignRequest sigReq, ResponseCodeMajor responseCode) {
        return getErrorResponse(encSigReq, sigReq, responseCode, SCResponseCodeMinor.absent, responseCode.getMessage());
    }

    private SignResponseDocument getErrorResponse(byte[] encSigReq, SignRequest sigReq, ResponseCodeMajor responseCode, SCResponseCodeMinor responseCodeMinor) {
        return getErrorResponse(encSigReq, sigReq, responseCode, responseCodeMinor, responseCode.getMessage());
    }

    private SignResponseDocument getErrorResponse(byte[] encSigReq, SignRequest sigReq, ResponseCodeMajor responseCode, String message) {
        return getErrorResponse(encSigReq, sigReq, responseCode, SCResponseCodeMinor.absent, message);
    }
    private SignResponseDocument getErrorResponse(byte[] encSigReq, SignRequest sigReq, ResponseCodeMajor responseCode, SCResponseCodeMinor responseCodeMinor, String message) {
        SignResponseDocument responseDoc = SignResponseDocument.Factory.newInstance();
        SignResponse response = responseDoc.addNewSignResponse();
        response.setProfile(PROTOCOL_PROFILE);
        SignResponseExtensionType eid2Response = response.addNewOptionalOutputs().addNewSignResponseExtension();
        eid2Response.setVersion(getProtocolVersion(sigReq));
        eid2Response.setResponseTime(Calendar.getInstance());
        if (encSigReq != null && sigReq != null) {
            eid2Response.setRequest(encSigReq);
            response.setRequestID(sigReq.getRequestID());
        }
        Result result = response.addNewResult();
        InternationalStringType resultMessage = result.addNewResultMessage();
        resultMessage.setLang("en");
        resultMessage.setStringValue(message);
        result.setResultMajor(responseCode.getCode());
        switch (responseCodeMinor){
        case absent:
            break;
        default:
            result.setResultMinor(responseCodeMinor.getCode());
        }

        return responseDoc;
    }

    private String getProtocolVersion(SignRequest sigReq) {
        try {
            String reqVersion = sigReq.getOptionalInputs().getSignRequestExtension().getVersion();
            if (reqVersion.equals(EID2_PROTOCOL_VERSION) || StringUtils.isEmpty(reqVersion)){
                return EID2_PROTOCOL_VERSION;
            }
            switch (reqVersion.trim()){
            case "1.2":
            case "1.3":
            case "1.4":
                return reqVersion.trim();
            default:
                return EID2_PROTOCOL_VERSION;
            }
        } catch (Exception ex){
            LOG.warning("Cant process sign request version");
            return CURRENT_EID2_PROTOCOL_VERSION;
        }
    }

    public static Node getResponseSignatureParent(SignResponseDocument sigResponseDoc) {
        SignResponse signResponse = sigResponseDoc.getSignResponse();
        if (signResponse == null) {
            sigResponseDoc.addNewSignResponse();
        }
        Eid2RespAnyType optionalOutputs = signResponse.getOptionalOutputs();
        if (optionalOutputs == null) {
            optionalOutputs = signResponse.addNewOptionalOutputs();
        }
        return optionalOutputs.getDomNode();
    }

    private String getTestPrint(byte[] xmlBytes, SignResponseExtensionType response) {
        // Test print 
        StringBuilder b = new StringBuilder();
        b.append(new String(xmlBytes, Charset.forName("UTF-8"))).append("\n");
        try {
            byte[][] signatureCertificates = response.getSignatureCertificateChain().getX509CertificateArray();
            for (byte[] b64Cert : signatureCertificates) {
                X509Certificate cert = CertificateUtils.getCertificate(b64Cert);
                if (cert != null) {
                    b.append(cert.toString(true)).append("\n");
                }
            }
        } catch (Exception ex) {
        }

        return b.toString();

    }

    private boolean getTimeValidity(ConditionsType conditions) {
        boolean valid = false;
        try {
            long present = System.currentTimeMillis();
            long notBefore = conditions.getNotBefore().getTime().getTime();
            long notAfter = conditions.getNotOnOrAfter().getTime().getTime();

            valid = (notBefore < present && present < notAfter);
        } catch (Exception ex) {
        }

        return valid;
    }

    private String getResponseUrl(SignRequest request) {
        try {
            ConditionsType conditions = request.getOptionalInputs().getSignRequestExtension().getConditions();
            return conditions.getAudienceRestrictionArray(0).getAudienceArray(0);
        } catch (Exception ex) {
        }
        return null;
    }


    public static class RequestAndResponse {

        private SignRequestDocument requestDoc;
        private SignResponseDocument responseDoc;

        public RequestAndResponse() {
        }

        public RequestAndResponse(SignRequestDocument request, SignResponseDocument reponse) {
            this.requestDoc = request;
            this.responseDoc = reponse;
        }

        public RequestAndResponse(SignRequestDocument request) {
            this.requestDoc = request;
        }

        public RequestAndResponse(SignResponseDocument reponse) {
            this.responseDoc = reponse;
        }

        public SignResponseDocument getReponseDoc() {
            return responseDoc;
        }

        public void setReponseDoc(SignResponseDocument reponseDoc) {
            this.responseDoc = reponseDoc;
        }

        public SignRequestDocument getRequestDoc() {
            return requestDoc;
        }

        public void setRequestDoc(SignRequestDocument requestDoc) {
            this.requestDoc = requestDoc;
        }

        public SignRequest getRequest() {
            if (requestDoc == null) {
                return null;
            }
            return requestDoc.getSignRequest();
        }

        public SignResponse getResponse() {
            if (responseDoc == null) {
                return null;
            }
            return responseDoc.getSignResponse();
        }
    }
}
