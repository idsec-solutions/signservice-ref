/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Response;

/**
 *
 * @author stefan
 */
public class ApResponse extends AbstractOpenSamlObj<Response> {

    public ApResponse() {
        super(Response.DEFAULT_ELEMENT_NAME);
        obj.setID(null);
        obj.setID(getNewID());
        obj.setIssueInstant(new DateTime());
        obj.setVersion(SAMLVersion.VERSION_20);
    }

    public ApResponse(Response obj) {
        super(obj, Response.DEFAULT_ELEMENT_NAME);
    }

    public void setStatus(SamlStatusCode code, String message) {
        ApStatus status = new ApStatus();
        status.setStatusCode(code).setStatusMessage(message);
        obj.setStatus(status.obj);
    }

    public void setStatus(SamlStatusCode code, SamlStatusCode secondCode, String message) {
        ApStatus status = new ApStatus();
        status.setStatusCode(code, secondCode).setStatusMessage(message);
        obj.setStatus(status.obj);
    }

    public void setIssuer(String issuerEntityId) {
        ApIssuer issuer = new ApIssuer();
        issuer.setIssuerEntityId(issuerEntityId);
        obj.setIssuer(issuer.obj);
    }

}
