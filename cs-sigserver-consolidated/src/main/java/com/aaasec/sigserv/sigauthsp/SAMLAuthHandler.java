/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import com.aaasec.sigserv.sigauthsp.models.AuthReqData;
import com.aaasec.sigserv.sigauthsp.models.AuthReqResult;
import com.aaasec.sigserv.sigauthsp.opensaml.ApRequest;
import com.aaasec.sigserv.sigauthsp.utils.OSUtil;

/**
 *
 * @author stefan
 */
public class SAMLAuthHandler {

    public static AuthReqResult getRequest(AuthReqData ard) {
        AuthReqResult result = new AuthReqResult();
        if (ard.getReqUrl() == null) {
            return result;
        }

        switch (ard.getType()) {
            case unsignedRedirect:
                return getRedirectLoginUrl(ard, false);
            case signedRedirect:
                return getRedirectLoginUrl(ard, true);
            case unsignedPost:
                ard.setKsBundle(null);
                return getPostXhtml(ard);
            case signedPost:
                return getPostXhtml(ard);
            default:
                throw new AssertionError(ard.getType().name());

        }
    }

    private static AuthReqResult getRedirectLoginUrl(AuthReqData ard, boolean signed) {
        AuthReqResult result = new AuthReqResult();
        result.setIdpEntityId(ard.getIdpEntityId());
        ApRequest request = OSUtil.getRequest(ard, OSUtil.redirectBinding);

        String authnRequestUrl;
        if (signed) {
            authnRequestUrl = OSUtil.getSignedAuthnRequestUrl(request, ard.getIdpEntityId(), ard.getReqUrl(), ard.getKsBundle());
        } else {
            authnRequestUrl = OSUtil.getAuthnRequestUrl(request, ard.getIdpEntityId(), ard.getReqUrl());
        }

        try {
            result.setRequest(request);
            result.setRequestType(ard.getType());
            result.setLoginData(authnRequestUrl);
            result.setReqId(request.obj.getID());
        } catch (Exception ex) {
        }
        return result;
    }

    private static AuthReqResult getPostXhtml(AuthReqData ard) {
        AuthReqResult result = new AuthReqResult();
        result.setIdpEntityId(ard.getIdpEntityId());
        ApRequest request = OSUtil.getRequest(ard, OSUtil.postBinding);
        if (ard.getKsBundle() != null) {
            try {
                OSUtil.signRequest(request, ard.getKsBundle());
            } catch (SecurityException | SignatureException | MarshallingException | CertificateEncodingException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
                Logger.getLogger(SAMLAuthHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        String reqXhtml = OSUtil.getRequestXhtmlForm(request, ard.getIdpEntityId(), ard.getReqUrl());
        if (reqXhtml == null) {
            return result;
        }

        try {
            result.setRequest(request);
            result.setRequestType(ard.getType());
            result.setLoginData(reqXhtml);
            result.setReqId(request.obj.getID());
        } catch (Exception ex) {
        }
        return result;

    }
}
