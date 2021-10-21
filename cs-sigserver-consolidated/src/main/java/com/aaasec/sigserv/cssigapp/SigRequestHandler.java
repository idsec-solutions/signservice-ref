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

import com.aaasec.lib.crypto.xml.SigVerifyResult;
import com.aaasec.lib.crypto.xml.SignedXmlDoc;
import com.aaasec.lib.crypto.xml.XMLSign;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.FnvHash;
import com.aaasec.sigserv.cscommon.XhtmlForm;
import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.cscommon.enums.SigTaskStatus;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.testdata.TestData;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import com.aaasec.sigserv.cssigapp.data.DbSignTask;
import com.aaasec.sigserv.cssigapp.data.ReqResult;
import com.aaasec.sigserv.cssigapp.data.SignAcceptPageInfo;
import com.aaasec.sigserv.cssigapp.db.SignTaskTable;
import com.aaasec.sigserv.cssigapp.instances.InstanceConfig;
import com.aaasec.sigserv.cssigapp.utils.NamedKeyStore;
import com.aaasec.sigserv.sigserver.auth.SignMessUtil;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;
import org.w3c.dom.Node;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignRequestExtensionType;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignResponseExtensionType;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignTaskDataType;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignTasksType;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0Assertion.oasisNamesTcSAML2.AudienceRestrictionType;
import x0Assertion.oasisNamesTcSAML2.ConditionsType;
import x0CoreSchema.oasisNamesTcDss1.InternationalStringType;
import x0CoreSchema.oasisNamesTcDss1.ResultDocument.Result;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument.SignRequest;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument;
import x0CoreSchema.oasisNamesTcDss1.SignResponseDocument.SignResponse;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

/**
 * Sig Request Handler
 */
public class SigRequestHandler {

    private static final long MAX_TIME = 1000 * 60 * 10;
    private final String storageLocation;
    private final SignTaskTable signDb;
    private final String sigTaskDir, sigTaskDbFile;
    private final String confDir;
    private final OldReqCleaner cleaner = new OldReqCleaner();
    private Thread cleanThread;

    public SigRequestHandler(String storageLocation) {
        this.storageLocation = storageLocation;
        sigTaskDir = FileOps.getfileNameString(storageLocation, "sigTasks");
        sigTaskDbFile = FileOps.getfileNameString(sigTaskDir, "sigTasks.db");
        signDb = new SignTaskTable(sigTaskDbFile);
        confDir = FileOps.getfileNameString(storageLocation, "conf");
    }

    public NamedKeyStore getInstanceKeystore(byte[] reqXml){
        try {
            SignRequestDocument signRequestDocument = SignRequestDocument.Factory.parse(new ByteArrayInputStream(reqXml));
            return getInstanceKeystore(signRequestDocument);

        } catch (Exception ex){
            return null;
        }
    }

    public NamedKeyStore getInstanceKeystore(SignRequestDocument signRequestDocument){
        try {
            String sigServiceEntityId = signRequestDocument.getSignRequest().getOptionalInputs().getSignRequestExtension().getSignService().getStringValue();
            InstanceConfig instanceConf = ContextParameters.getInstanceConf();
            String sigInstanceName = instanceConf.getEntityIdInstanceName(sigServiceEntityId);
            NamedKeyStore instKs = instanceConf.getInstanceKeyStoreMap().get(sigInstanceName);
            return instKs;
        } catch (Exception ex){
            return null;
        }
    }

    public ReqResult handeSignRequest(byte[] reqXml) {
        ReqResult reqResult;
        byte[] encSigReq = reqXml;
        String reqText = new String(reqXml, Charset.forName("UTF-8"));
        //Cleanup old requests
        removeOldRequests();
        //Get request
        SignRequestDocument sigReqDoc;
        SignRequest sigReq = null;
        SignRequestExtensionType eid2Req = null;
        NamedKeyStore instanceKs = null;
        try {
            sigReqDoc = SignRequestDocument.Factory.parse(new ByteArrayInputStream(reqXml));
            sigReq = sigReqDoc.getSignRequest();
            eid2Req = sigReq.getOptionalInputs().getSignRequestExtension();
            instanceKs = getInstanceKeystore(sigReqDoc);
        } catch (Exception ex) {
        }
        if (eid2Req == null) {
            return new ReqResult(Enums.ResponseCodeMajor.InsufficientInfo, "", "");
        }

        // Get response URL and check validity period
        String spUrl = "";
        try {
            ConditionsType conditions = eid2Req.getConditions();
            AudienceRestrictionType[] audienceRestrictions = conditions.getAudienceRestrictionArray();
            for (AudienceRestrictionType audRest : audienceRestrictions) {
                spUrl = audRest.getAudienceArray(0);
            }
            Calendar notBefore = conditions.getNotBefore();
            Calendar notOnOrAfter = conditions.getNotOnOrAfter();
            if (!isConditionsTimeValid(notBefore, notOnOrAfter)) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Invalid validity period");
                setErrorResponse(reqResult, encSigReq, instanceKs);
                return reqResult;
            }
        } catch (Exception ex) {
            return new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", "");
        }

        String id = "";
        try {

            id = sigReq.getRequestID();
            // check id quality
            if (id.length() < 20) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Request ID is too short (at least 20 bytes)");
                setErrorResponse(reqResult, encSigReq, instanceKs);
                return reqResult;
            }
            //Check if request is a replay            
            DbSignTask dbRecord = signDb.getDbRecord(id);
            if (dbRecord != null) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", "", "Replay of old request");
                return reqResult;
            }

            //Check if the same user has another unfinished sign task being serviced
            String userIdpId = getUserIdpId(eid2Req);
            if (ContextParameters.isPreventDuplicateUserTasks()) {
                boolean hasOtherSignTask = isDuplicateSignTask(userIdpId);
                if (hasOtherSignTask) {
                    reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "User has multipple requests under service");
                    setErrorResponse(reqResult, encSigReq, instanceKs);
                    return reqResult;
                }
            }

            //Check signature
            SigVerifyResult verifySignature = XMLSign.verifySignature(reqXml);
            if (!verifySignature.valid) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", "", "Bad signature on request");
                return reqResult;
            }

            //Check that appropriate Sign Service was specified
            InstanceConfig instanceConf = ContextParameters.getInstanceConf();
            String sigServiceEntityId = null;
            String instanceName = null;
            try {
                sigServiceEntityId = eid2Req.getSignService().getStringValue();
                instanceName = instanceConf.getEntityIdInstanceName(sigServiceEntityId);
                if (instanceName == null) {
                    reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Unrecognized Sign Service Entity ID");
                    setErrorResponse(reqResult, encSigReq, instanceKs);
                    return reqResult;
                }
            } catch (Exception e) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Unrecognized Sign Service Entity ID");
                setErrorResponse(reqResult, encSigReq, instanceKs);
                return reqResult;
            }
            
            //Check if sign requester is in trust store
            String signRequesterEntityId = eid2Req.getSignRequester().getStringValue();
            if (!instanceConf.getTrustedSigners().contains(signRequesterEntityId)){
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", "", "Requesting service ID is unknown");
                return reqResult;                
            }
            
            // Check that key is trusted
            List<PublicKey> trustedKeys = instanceConf.getTrustedPublicKeyMap().get(instanceName);
            PublicKey requesterPk = verifySignature.cert.getPublicKey();
            boolean trustedRequester = false;
            for (PublicKey trustedKey : trustedKeys) {
                if (Arrays.equals(requesterPk.getEncoded(), trustedKey.getEncoded())) {
                    trustedRequester = true;
                    break;
                }
            }

            if (!trustedRequester) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", "", "Requesting service provider is not in trust store");
                return reqResult;
            }

            //Check age
            long reqTime = eid2Req.getRequestTime().getTimeInMillis();
            if (reqTime + MAX_TIME < System.currentTimeMillis()) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", "", "Request has expired");
                return reqResult;
            }

            //Check if request time is in the future
            if (System.currentTimeMillis() + 60000 < reqTime) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", "", "Illegal request time");
                return reqResult;
            }

            // Get Idp Entity Id
            String idpEntityId = null;
            try {
                idpEntityId = eid2Req.getIdentityProvider().getStringValue();
            } catch (Exception ex) {
            }
            if (idpEntityId == null) {
                return new ReqResult(Enums.ResponseCodeMajor.InsufficientInfo, id, spUrl, "Missing Identity Provider reference");
            }

            SigAlgorithmCheck sigAlgoCheck = new SigAlgorithmCheck(sigReq);
            if (!sigAlgoCheck.isValidAlgoRequest()) {
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Illegal signature algorithm request");
                setErrorResponse(reqResult, encSigReq, instanceKs);
                return reqResult;
            }


            //Check that request has signature request data
            boolean hasValidRequestData=true;
            try {
                SignTasksType signTasks = sigReq.getInputDocuments().getOtherArray(0).getSignTasks();
                SignTaskDataType[] signTaskDataArray = signTasks.getSignTaskDataArray();
                if (signTaskDataArray==null || signTaskDataArray.length<1){
                    hasValidRequestData=false;
                }
                for (SignTaskDataType std: signTaskDataArray){
                    if (std.getToBeSignedBytes().length < 10){
                        hasValidRequestData=false;
                    }
                    if (std.getAdESType() == null){
                        hasValidRequestData=false;
                    }
                    if (std.getSigType() == null){
                        hasValidRequestData=false;
                    }
                }
            } catch (Exception ex){
                hasValidRequestData=false;
            }
            if (!hasValidRequestData){
                reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, "", spUrl, "Invalid signature request data");
                setErrorResponse(reqResult, encSigReq, instanceKs);
                return reqResult;
            }

            // Store new sign task
            String sigMessage = SignMessUtil.getSignMessageB64(eid2Req.getSignMessage());
            SignAcceptPageInfo pageInfo = new SignAcceptPageInfo();
            pageInfo.sigReuestDeclineUrl = spUrl + "?action=declined";
            pageInfo.requesterName = eid2Req.getSignRequester().getStringValue();
            pageInfo.signingInstanceNonce = id;
            // Store dbRecord
            DbSignTask dbSig = new DbSignTask();
            dbSig.setId(id).setRequest(reqXml).setTime(System.currentTimeMillis());
            dbSig.setSignMessage(sigMessage.getBytes(Charset.forName("UTF-8")));
            dbSig.setPageInfo(pageInfo);
            dbSig.setUserIdpId(userIdpId);
            dbSig.setStatus(SigTaskStatus.Received);
            signDb.addOrReplaceRecord(dbSig);

            reqResult = new ReqResult(Enums.ResponseCodeMajor.Success, id, spUrl);
            reqResult.idpEntityId = idpEntityId;
            reqResult.signServiceEntityId = sigServiceEntityId;

            return reqResult;
        } catch (Exception ex) {
            return new ReqResult(Enums.ResponseCodeMajor.BadRequest, id, spUrl);
        }

    }

    /**
     * Generates an error response XHTML and incorporates this in the ReqResult object.
     * @param reqRes the result object
     * @param encSigReq encoded Sign Request or null if absent
     */
    public static void setErrorResponse(ReqResult reqRes, byte[] encSigReq, NamedKeyStore instanceKs) {
        SignResponseDocument responseDoc = SignResponseDocument.Factory.newInstance();
        SignResponse response = responseDoc.addNewSignResponse();
            String protProfile = "http://id.elegnamnden.se/csig/1.1/dss-ext/profile";
        String reqId = reqRes.id == null ? "" : reqRes.id;
        try {
            SignRequestDocument reqDoc = SignRequestDocument.Factory.parse(new ByteArrayInputStream(encSigReq));
            SignRequest signRequest = reqDoc.getSignRequest();
            protProfile = signRequest.getProfile();
            reqId = signRequest.getRequestID();
        } catch (Exception ex) {
        }
        response.setProfile(protProfile);
        response.setRequestID(reqId);
        Result result = response.addNewResult();
        InternationalStringType resultMess = result.addNewResultMessage();
        resultMess.setLang("en");
        resultMess.setStringValue(reqRes.message);
        result.setResultMajor(reqRes.code);
        SignResponseExtensionType eid2Resp = response.addNewOptionalOutputs().addNewSignResponseExtension();
        eid2Resp.setVersion("1.1");
        if (encSigReq != null) {
            eid2Resp.setRequest(encSigReq);
        }
        eid2Resp.setResponseTime(Calendar.getInstance());

        byte[] responseXml = XmlBeansUtil.getStyledBytes(responseDoc);
        // attempt to sign response;
        if (instanceKs != null){
            Node sigParent = SignatureCreationHandler.getResponseSignatureParent(responseDoc);
            SignedXmlDoc signedXML = XMLSign.getSignedXML(responseXml, instanceKs.getPrivate(), instanceKs.getKsCert(), sigParent, true, false);
            responseXml = signedXML.sigDocBytes;
        }

        String errorResponseForm = XhtmlForm.getSignXhtmlForm(XhtmlForm.Type.SIG_RESPONSE_FORM, reqRes.spUrl, responseXml, reqId);
        reqRes.errorResponse = errorResponseForm;

        // Store testData
        TestData.storeXhtmlResponse(reqId, errorResponseForm);
        TestData.storeResponse(reqId, responseXml);

    }

    /**
     * Injects runnable daemontask, removing requests older than 20 minutes
     */
    private void removeOldRequests() {
        if (running(cleanThread)) {
            return;
        }
        cleanThread = new Thread(cleaner);
        cleanThread.setDaemon(true);
        cleanThread.start();
    }

    private boolean running(Thread thread) {
        return (thread != null && thread.isAlive());
    }

    private String getUserIdpId(SignRequestExtensionType eid2Req) {
        StringBuilder b = new StringBuilder();
        try {
            AttributeType[] attributeArray = eid2Req.getSigner().getAttributeArray();
            String idpEntityId = eid2Req.getIdentityProvider().getStringValue();
            b.append(idpEntityId);
            for (AttributeType attr : attributeArray) {
                b.append(attr.getName());
                XmlObject[] attributeValueArray = attr.getAttributeValueArray();
                for (XmlObject attrVal : attributeValueArray) {
                    XmlString strVal = (XmlString) attrVal;
                    b.append(strVal.getStringValue());
                }
            }
            return FnvHash.getFNV1a(b.toString()).toString(16);
        } catch (Exception ex) {
            return null;
        }
    }

    private boolean isDuplicateSignTask(String userIdpId) {
        //Excluding serviced requests
        boolean duplicate = false;
        List<DbSignTask> records = signDb.getRecords("UserIdpId", userIdpId);
        for (DbSignTask task : records) {
            if (task.getStatus().equals(SigTaskStatus.Received)) {
                duplicate = true;
                // Mark in the original sign task that a duplicate request has been received before first task is processed.
                task.setStatus(SigTaskStatus.DuplicateUserReq);
                signDb.addOrReplaceRecord(task);
            }
        }
        return duplicate;
    }

    private boolean isConditionsTimeValid(Calendar notBefore, Calendar notOnOrAfter) {
        Calendar current = Calendar.getInstance();
        Calendar maxTime = Calendar.getInstance();
        maxTime.add(Calendar.MILLISECOND, (int) MAX_TIME);
        if (current.before(notBefore)) {
            return false;
        }
        if (current.after(notOnOrAfter)) {
            return false;
        }

        maxTime.add(Calendar.MINUTE, 1);
        return !notOnOrAfter.after(maxTime);
    }

    class OldReqCleaner implements Runnable {

        long lastCleanup = 0;

        public OldReqCleaner() {
        }

        public void run() {
            long current = System.currentTimeMillis();
            //Skip if last cleanup was less than Max Time;
            if (current < lastCleanup + MAX_TIME) {
                return;
            }
            List<DbSignTask> allRecords = signDb.getAllRecords();
            for (DbSignTask sigTask : allRecords) {
                if (current > sigTask.getTime() + MAX_TIME) {
                    signDb.deteleDbRecord(sigTask);
                }
            }
            lastCleanup = System.currentTimeMillis();
        }
    }
}
