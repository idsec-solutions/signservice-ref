/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.utils;

import com.aaasec.lib.crypto.xml.SigVerifyResult;
import com.aaasec.lib.crypto.xml.XMLSign;
import com.aaasec.lib.crypto.xml.XmlUtils;
import com.aaasec.lib.utils.Base64Coder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

import com.aaasec.sigserv.sigauthsp.models.KeyStoreBundle;
import com.aaasec.sigserv.sigauthsp.opensaml.AbstractOpenSamlObj;
import com.aaasec.sigserv.sigauthsp.opensaml.ApAssertion;
import com.aaasec.sigserv.sigauthsp.opensaml.ApResponse;
import com.aaasec.sigserv.sigauthsp.opensaml.Builder;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;

/**
 *
 * @author stefan
 */
public class ApResponseHandler {

    private Assertion assertion;
    private final ApCredential clientCredential;
    private final ApCredential apServiceCredential;
    private final Response response;
    private final OsSigvalResult ResponseSignature;
    private final OsSigvalResult AssertionSignature;

    public ApResponseHandler(String b64Response, KeyStoreBundle spCredential, byte[] apServiceCert) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {
        this(unmarshallB64Response(b64Response), new ApCredential(spCredential), new ApCredential(apServiceCert));
    }

    public ApResponseHandler(Response response, ApCredential clientCredential, ApCredential apServiceCredential) {
        this.clientCredential = clientCredential;
        this.apServiceCredential = apServiceCredential;
        this.response = response;
        ResponseSignature = validateSignature(new ApResponse(response));
        getAssertion();
//        ResponseSignature = new OsSigvalResult();
        AssertionSignature = validateSignature(new ApAssertion(assertion));
    }

    public static final Response unmarshallB64Response(String b64Response) {
        try {
            Unmarshaller unmarshaller = Builder.unmarshallerFactory.getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);
            Document responseDoc = XmlUtils.getDocument(Base64Coder.decodeLines(b64Response));
            return (Response) unmarshaller.unmarshall(responseDoc.getDocumentElement());

        } catch (Exception ex) {
        }
        return null;
    }

    public ApAssertion getDecryptedAssertion() {
        if (assertion != null) {
            return new ApAssertion(assertion);
        }
        return null;
    }

    public OsSigvalResult getResponseSignatureValidation() {
        return ResponseSignature;
    }

    public OsSigvalResult getAssertionSignatureValidation() {
        return AssertionSignature;
    }

    public Response getResponse() {
        return response;
    }
    
    public ApResponse getApResponse(){
        ApResponse apResponse = new ApResponse(response);
        return apResponse;
    }

    private void getAssertion() {
        List<Assertion> assertions = response.getAssertions();
        List<EncryptedAssertion> encryptedAssertions = response.getEncryptedAssertions();
        if (encryptedAssertions.size() > 0) {
            try {
                assertion = EncryptAssertionUtil.decrypt(encryptedAssertions.get(0), clientCredential.getCredential());
            } catch (DecryptionException e) {
                e.printStackTrace();
            }
            return;
        }
        if (assertions.size() > 0) {
            assertion = assertions.get(0);
        }
    }

    private OsSigvalResult validateSignature(AbstractOpenSamlObj samlObj) {
        SignableSAMLObject signedObject;
        try {
            signedObject = (SignableSAMLObject) samlObj.obj;
            if (signedObject.getSignature() == null) {
                // Signable object is not signed
                return new OsSigvalResult();
            }
        } catch (Exception ex) {
            // This is not a signable object;
            return new OsSigvalResult();
        }

        // Verify signature
        try {
            // This prevalidation is done in order to set the ID attributes as ID.
            // This is necessary for the validaiton process against the credentials.
            SigVerifyResult verifySignature = XMLSign.verifySignature(samlObj.getXmlDoc());

            //OpenSAML validation (Validates against signer certificate)
            SignatureValidator validator = new SignatureValidator(apServiceCredential.getCredential());
            validator.validate(signedObject.getSignature());
            if (verifySignature.valid) {
                // valid signature
                return new OsSigvalResult(true, verifySignature.cert);
            }
            return new OsSigvalResult(false);
        } catch (ValidationException ex) {
            // signature validation exception
            return new OsSigvalResult(ex);
        }
    }

}
