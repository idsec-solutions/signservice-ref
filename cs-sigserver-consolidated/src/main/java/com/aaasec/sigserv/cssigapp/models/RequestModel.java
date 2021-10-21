/*
 * Copyright 2013 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *   Licensed under the EUPL, Version 1.1 or ñ as soon they will be approved by the 
 *   European Commission - subsequent versions of the EUPL (the "Licence");
 *   You may not use this work except in compliance with the Licence. 
 *   You may obtain a copy of the Licence at:
 * 
 *   http://joinup.ec.europa.eu/software/page/eupl 
 * 
 *   Unless required by applicable law or agreed to in writing, software distributed 
 *   under the Licence is distributed on an "AS IS" basis,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
 *   implied.
 *   See the Licence for the specific language governing permissions and limitations 
 *   under the Licence.
 */
package com.aaasec.sigserv.cssigapp.models;

import com.aaasec.sigserv.cscommon.data.AuthData;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Model for HTTP requests
 */
public class RequestModel {

    private String id = "";
    private Map<String, List<String>> authAttributeMap;
    private AuthData authData;
    private Date authInstant;
    private Date issueIntant;

    public RequestModel() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Map<String, List<String>> getAuthAttributeMap() {
        return authAttributeMap;
    }

    public void setAuthAttributeMap(Map<String, List<String>> authAttributeMap) {
        this.authAttributeMap = authAttributeMap;
    }

    public AuthData getAuthData() {
        return authData;
    }

    public void setAuthData(AuthData authData) {
        this.authData = authData;
    }

    public Date getAuthInstant() {
        return authInstant;
    }

    public void setAuthInstant(Date authInstant) {
        this.authInstant = authInstant;
    }

    public Date getIssueIntant() {
        return issueIntant;
    }

    public void setIssueIntant(Date issueIntant) {
        this.issueIntant = issueIntant;
    }
    
}
