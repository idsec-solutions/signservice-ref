/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import org.opensaml.saml2.core.AuthnRequest;

/**
 *
 * @author stefan
 */
public class ApRequest extends AbstractOpenSamlObj<AuthnRequest>{

    public ApRequest() {
        super(AuthnRequest.DEFAULT_ELEMENT_NAME);
    }

    public ApRequest(AuthnRequest obj) {
        super(obj, AuthnRequest.DEFAULT_ELEMENT_NAME);
    }    
}
