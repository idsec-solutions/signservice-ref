/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.models;

/**
 *
 * @author stefan
 */
public class ResponseSigDataModel {
    private byte[] signature;
    private byte[] tbsBytes;
    private byte[] adesObjBytes;
    private String signatureId;
    private boolean adesSig = false;

    public ResponseSigDataModel() {
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public byte[] getTbsBytes() {
        return tbsBytes;
    }

    public void setTbsBytes(byte[] tbsBytes) {
        this.tbsBytes = tbsBytes;
    }

    public byte[] getAdesObjBytes() {
        return adesObjBytes;
    }

    public void setAdesObjBytes(byte[] adesObjBytes) {
        this.adesObjBytes = adesObjBytes;
    }

    public String getSignatureId() {
        return signatureId;
    }

    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }

    public boolean isAdesSig() {
        return adesSig;
    }

    public void setAdesSig(boolean adesSig) {
        this.adesSig = adesSig;
    }
    
    
}


