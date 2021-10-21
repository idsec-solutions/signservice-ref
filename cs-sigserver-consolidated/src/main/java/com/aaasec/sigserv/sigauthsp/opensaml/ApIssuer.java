/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import org.opensaml.saml2.core.Issuer;

/**
 *
 * @author stefan
 */
public class ApIssuer extends AbstractOpenSamlObj<Issuer>{

    public ApIssuer() {
        super(Issuer.DEFAULT_ELEMENT_NAME);
    }

    public ApIssuer(Issuer obj) {
        super(obj, Issuer.DEFAULT_ELEMENT_NAME);
    }
    
    public ApIssuer setIssuerEntityId(String entityId){
        obj.setValue(entityId);
        obj.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        return this;
    }
}
