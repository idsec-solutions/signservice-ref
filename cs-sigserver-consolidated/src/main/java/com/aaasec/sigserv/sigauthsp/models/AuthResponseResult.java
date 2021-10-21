/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.models;

import com.aaasec.sigserv.sigauthsp.opensaml.ApResponse;
import org.opensaml.saml2.core.Assertion;

/**
 *
 * @author stefan
 */
public class AuthResponseResult {
    private String inResponseToId;
    private ApResponse response;
    private boolean validSignature;
    private Assertion assertion;
    private byte[] assertionBytes;

    public AuthResponseResult() {
    }

    public String getInResponseToId() {
        return inResponseToId;
    }

    public void setInResponseToId(String inResponseToId) {
        this.inResponseToId = inResponseToId;
    }

    public ApResponse getResponse() {
        return response;
    }

    public void setResponse(ApResponse response) {
        this.response = response;
    }

    public boolean isValidSignature() {
        return validSignature;
    }

    public void setValidSignature(boolean validSignature) {
        this.validSignature = validSignature;
    }

    public Assertion getAssertion() {
        return assertion;
    }

    public void setAssertion(Assertion assertion) {
        this.assertion = assertion;
    }

    public byte[] getAssertionBytes() {
        return assertionBytes;
    }

    public void setAssertionBytes(byte[] assertionBytes) {
        this.assertionBytes = assertionBytes;
    }
    
    
    
}
