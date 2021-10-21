/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import java.util.List;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.RequestedAuthnContext;

/**
 *
 * @author stefan
 */
public class ApReqAuthContextClass extends AbstractOpenSamlObj<RequestedAuthnContext> {

    public ApReqAuthContextClass() {
        super(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
    }

    public ApReqAuthContextClass(RequestedAuthnContext obj) {
        super(obj, RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
    }

    public void setAuthContextClassRef(List<String> authContextClassRefUri) {
        List<AuthnContextClassRef> authnContextClassRefs = obj.getAuthnContextClassRefs();
        for (String classRef : authContextClassRefUri) {
            ApAuthContextClassRef accRef = new ApAuthContextClassRef();
            accRef.obj.setAuthnContextClassRef(classRef);
            authnContextClassRefs.add(accRef.obj);
        }
    }

}
