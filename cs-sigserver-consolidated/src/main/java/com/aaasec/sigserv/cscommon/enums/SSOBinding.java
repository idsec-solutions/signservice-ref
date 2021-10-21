/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cscommon.enums;

/**
 *
 * @author stefan
 */
public enum SSOBinding {
    redirect("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"),
    post("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
    
    String bindginURI;

    private SSOBinding(String bindginURI) {
        this.bindginURI = bindginURI;
    }

    public String getBindginURI() {
        return bindginURI;
    }    
}
