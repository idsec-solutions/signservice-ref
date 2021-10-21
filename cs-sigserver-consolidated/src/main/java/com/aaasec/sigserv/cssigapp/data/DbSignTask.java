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
package com.aaasec.sigserv.cssigapp.data;

import com.aaasec.sigserv.cscommon.enums.SigTaskStatus;

/**
 * Database model for sign tasks.
 */
public class DbSignTask {

    private String id;
    private long time = 0, serviced = 0;
    private SigTaskStatus status;
    private String userIdpId;
    private byte[] request = null;
    private byte[] signMessage;
    private SignAcceptPageInfo pageInfo;

    public DbSignTask() {
    }

    public String getId() {
        return id;
    }

    public DbSignTask setId(String id) {
        this.id = id;
        return this;
    }

    public byte[] getRequest() {
        return request;
    }

    public DbSignTask setRequest(byte[] request) {
        this.request = request;
        return this;
    }

    public long getTime() {
        return time;
    }

    public DbSignTask setTime(long time) {
        this.time = time;
        return this;
    }

    public long getServiced() {
        return serviced;
    }

    public DbSignTask setServiced(long serviced) {
        this.serviced = serviced;
        return this;
    }

    public SignAcceptPageInfo getPageInfo() {
        return pageInfo;
    }

    public void setPageInfo(SignAcceptPageInfo pageInfo) {
        this.pageInfo = pageInfo;
    }

    public byte[] getSignMessage() {
        return signMessage;
    }

    public void setSignMessage(byte[] signMessage) {
        this.signMessage = signMessage;
    }

    public String getUserIdpId() {
        return userIdpId;
    }

    public void setUserIdpId(String userIdpId) {
        this.userIdpId = userIdpId;
    }

    public SigTaskStatus getStatus() {
        return status;
    }

    public void setStatus(SigTaskStatus status) {
        this.status = status;
    }    
    
}
