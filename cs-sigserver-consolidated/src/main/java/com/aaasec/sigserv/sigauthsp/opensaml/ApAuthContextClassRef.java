/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import org.opensaml.saml2.core.AuthnContextClassRef;

/**
 *
 * @author stefan
 */
public class ApAuthContextClassRef extends AbstractOpenSamlObj<AuthnContextClassRef>{

    public ApAuthContextClassRef() {
        super(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    }

    public ApAuthContextClassRef(AuthnContextClassRef obj) {
        super(obj, AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
    }
    
}
