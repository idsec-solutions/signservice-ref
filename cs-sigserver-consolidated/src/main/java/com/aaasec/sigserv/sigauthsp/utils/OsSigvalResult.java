/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.utils;

import java.security.cert.X509Certificate;

/**
 *
 * @author stefan
 */
public class OsSigvalResult {
    private boolean signed = false;
    private boolean validSignature;
    private Exception ex;
    private X509Certificate cert = null;

    public OsSigvalResult() {
    }

    public OsSigvalResult(boolean validSignature) {
        this.validSignature = validSignature;
        signed=true;
        ex=null;
    }    
    public OsSigvalResult(boolean validSignature, X509Certificate cert) {
        this.validSignature = validSignature;
        this.cert = cert;
        signed=true;
        ex=null;
    }    

    public OsSigvalResult(Exception ex) {
        this.ex = ex;
        signed = true;
        validSignature = false;
    }

    public boolean isSigned() {
        return signed;
    }

    public boolean isValidSignature() {
        return validSignature;
    }

    public Exception getEx() {
        return ex;
    }

    public X509Certificate getCert() {
        return cert;
    }
    
    
}
