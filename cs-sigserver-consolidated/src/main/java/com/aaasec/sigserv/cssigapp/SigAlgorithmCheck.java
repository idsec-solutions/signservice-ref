/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp;

import com.aaasec.lib.crypto.xml.XMLSign;
import com.aaasec.sigserv.cscommon.SigAlgorithms;
import java.io.ByteArrayInputStream;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.w3.x2000.x09.xmldsig.ReferenceType;
import org.w3.x2000.x09.xmldsig.SignedInfoDocument;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignRequestExtensionType;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignTaskDataType;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument.SignRequest;

/**
 *
 * @author stefan
 */
public class SigAlgorithmCheck {

    private static final Logger LOG = Logger.getLogger(SigAlgorithmCheck.class.getName());
    String requestedSignatureAlgorithm;
    SignTaskDataType[] signTaskDataArray;
    boolean initFailed = false;

    SigAlgorithmCheck(SignRequest sigReq) {
        try {
            SignRequestExtensionType eid2req = sigReq.getOptionalInputs().getSignRequestExtension();
            requestedSignatureAlgorithm = eid2req.getRequestedSignatureAlgorithm();
            signTaskDataArray = sigReq.getInputDocuments().getOtherArray(0).getSignTasks().getSignTaskDataArray();
        } catch (Exception e) {
            initFailed = true;
        }
    }

    boolean isValidAlgoRequest() {
        SigAlgorithms sigAlgo = SigAlgorithms.getSelectedAlgoByURI(requestedSignatureAlgorithm);
        if (sigAlgo.equals(SigAlgorithms.UNSUPPORTED)) {
            return false;
        }

        // Cehcking SignTaskData for consisence.
        for (SignTaskDataType std : signTaskDataArray) {
            SignTaskDataType.SigType.Enum sigType = std.getSigType();
            
            if (!sigType.equals(SignTaskDataType.SigType.XML) && !sigType.equals(SignTaskDataType.SigType.PDF)){
                return false;
            }
            if (sigType.equals(SignTaskDataType.SigType.XML)){
                if (!checkXmlfTbsData(requestedSignatureAlgorithm, sigAlgo.getDigestAlgo(), std.getToBeSignedBytes())){
                    return false;
                }                
            }
            if (sigType.equals(SignTaskDataType.SigType.PDF)){
                if (!checkPdfTbsData(sigAlgo.getDigestAlgo(), std.getToBeSignedBytes())){
                    return false;
                }                
            }
        }
        return true;
    }

    private boolean checkPdfTbsData(String hashAlgo, byte[] toBeSignedBytes) {
        try {
            ASN1InputStream ain = new ASN1InputStream(toBeSignedBytes);
            ASN1Set sigAttrSet = (ASN1Set) ain.readObject();
            for (int i = 0; i < sigAttrSet.size(); i++) {
                ASN1Sequence attr = (ASN1Sequence) sigAttrSet.getObjectAt(i);
                ASN1ObjectIdentifier attrId = (ASN1ObjectIdentifier) attr.getObjectAt(0);
                if (attrId.getId().equalsIgnoreCase("1.2.840.113549.1.9.4")) {
                    ASN1Set hashSet = (ASN1Set) attr.getObjectAt(1);
                    ASN1OctetString hashOs = (ASN1OctetString) hashSet.getObjectAt(0);
                    int hashLen = hashOs.getOctets().length * 8;

                    if (hashAlgo.equalsIgnoreCase(XMLSign.SHA1) && hashLen == 160) {
                        return true;
                    }
                    if (hashAlgo.equalsIgnoreCase(XMLSign.SHA256) && hashLen == 256) {
                        return true;
                    }
                    LOG.warning("SigResponse check: Error - PDF doc hash bit length incompatible with requested signature algo");
                    return false;
                }
            }
            LOG.warning("SigResponse check: Error - PDF doc hash not found");
            return false;
        } catch (Exception ex) {
            LOG.warning("SigResponse check: Error - Unable to parse PDF signed attributes " + ex.getMessage());
        }
        return false;
    }

    private boolean checkXmlfTbsData(String requestedSignatureAlgorithm, String hashAlgo, byte[] toBeSignedBytes) {
        try {
            SignedInfoDocument sigInfoDoc = SignedInfoDocument.Factory.parse(new ByteArrayInputStream(toBeSignedBytes));
            String algorithm = sigInfoDoc.getSignedInfo().getSignatureMethod().getAlgorithm();
            if (!algorithm.equals(requestedSignatureAlgorithm)) {
                LOG.warning("SigResponseCheck: Error - Delivered sig algo do not match requested algo");
                return false;
            }
            boolean success = true;
            ReferenceType[] referenceArray = sigInfoDoc.getSignedInfo().getReferenceArray();
            for (ReferenceType ref : referenceArray) {
                String refAlgo = ref.getDigestMethod().getAlgorithm();
                if (refAlgo.equals(XMLSign.SHA256) && hashAlgo.equals(XMLSign.SHA256)) {
                    continue;
                }
                if (refAlgo.equals(XMLSign.SHA1) && hashAlgo.equals(XMLSign.SHA1)) {
                    continue;
                }
                LOG.warning("SigRespnse Check: ERROR - Requested algorithm do not match reference hash algo");
                success = false;
            }
            return success;
        } catch (Exception ex) {
            LOG.warning("SigResponse check: Error - Unable to parse XML SignedInfo " + ex.getMessage());
        }
        return false;
    }

}
