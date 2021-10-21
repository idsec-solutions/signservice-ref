/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.models;

import com.aaasec.sigserv.sigauthsp.opensaml.ApRequest;

/**
 *
 * @author stefan
 */
public class AuthReqResult {
    private RequestType requestType;
    private String loginData;
    private ApRequest request;
    private String reqId;
    private String idpEntityId;
    private AuthReqData authReqData;

    public AuthReqResult() {
    }

    public RequestType getRequestType() {
        return requestType;
    }

    public void setRequestType(RequestType requestType) {
        this.requestType = requestType;
    }

    public String getLoginData() {
        return loginData;
    }

    public void setLoginData(String loginData) {
        this.loginData = loginData;
    }

    public ApRequest getRequest() {
        return request;
    }

    public void setRequest(ApRequest request) {
        this.request = request;
    }

    public String getReqId() {
        return reqId;
    }

    public void setReqId(String reqId) {
        this.reqId = reqId;
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public void setIdpEntityId(String idpEntityId) {
        this.idpEntityId = idpEntityId;
    }

    public AuthReqData getAuthReqData() {
        return authReqData;
    }

    public void setAuthReqData(AuthReqData authReqData) {
        this.authReqData = authReqData;
    }
    
}
