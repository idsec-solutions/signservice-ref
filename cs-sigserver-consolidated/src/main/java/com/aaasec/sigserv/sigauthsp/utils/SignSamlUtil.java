/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.utils;

import com.aaasec.lib.utils.Base64Coder;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import com.aaasec.sigserv.sigauthsp.opensaml.Builder;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author stefan
 */
public class SignSamlUtil {

    private final static Logger logger = LoggerFactory.getLogger(SignSamlUtil.class);

    private SignSamlUtil() {
    }

    public static void sign(SignableSAMLObject tbsObject, ApCredential signingCredential) throws SecurityException, SignatureException, MarshallingException, CertificateEncodingException {
        Signature signature = getSignatureElement(signingCredential);
        tbsObject.setSignature(signature);
        Builder.marshallerFactory.getMarshaller(tbsObject).marshall(tbsObject);
        Signer.signObject(signature);
    }

    private static Signature getSignatureElement(ApCredential signingCredential) throws CertificateEncodingException {
        Signature signature = Builder.signatureBuilder.buildObject();
        signature.setSigningCredential(signingCredential.getCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
//        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setKeyInfo(getKeyInfo(signingCredential.getCertificate()));
//        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
//        String keyInfoGeneratorProfile = "XMLSignature";
//        SecurityHelper.prepareSignatureParams(signature, signingCredential.getCredential(), secConfig, null);
        return signature;
    }

    private static KeyInfo getKeyInfo(Certificate x509cert) throws CertificateEncodingException {
        KeyInfo keyInfo = Builder.keyInfoBuilder.buildObject();
        X509Data x509Data = Builder.x509DataBuilder.buildObject();
        X509Certificate cert = Builder.x509CertificateBuilder.buildObject();
        List<X509Data> x509DataList = keyInfo.getX509Datas();
        x509DataList.add(x509Data);
        List<X509Certificate> x509Certificates = x509Data.getX509Certificates();
        x509Certificates.add(cert);
        cert.setValue(String.valueOf(Base64Coder.encode(x509cert.getEncoded())));
        return keyInfo;
    }

    public static boolean validateAssertionSignature(Assertion assertion, Credential signerCertCredential) {
        if (assertion == null || assertion.getSignature() == null) {
            return false;
        }

        SignatureValidator validator = new SignatureValidator(signerCertCredential);
        try {
            validator.validate(assertion.getSignature());
            return true;
        } catch (ValidationException ex) {
            return false;
        }
    }

}
