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
package com.aaasec.sigserv.cscommon.enums;

/**
 * Sign support status codes
 */
public enum SpsStatus {

    OK(101, "Operation successful"),
    NoSignTask(201, "No signing task in request"),
    IllegalDocType(202, "Illegal document type"),
    ReqGenError(203, "Failed to generate sign request"),
    FailedSigCompletion(301, "Failed to complete signing process"),
    FailedValidation(401, "Signature Validation Failed"),
    NoValidationPolicy(402, "No signature validation policy");
    private int code;
    private String message;

    private SpsStatus(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public static SpsStatus getStatusFromCode(int inpCode) {
        SpsStatus[] values = values();
        for (SpsStatus status : values) {
            if (status.code == inpCode) {
                return status;
            }
        }
        return null;
    }
}
