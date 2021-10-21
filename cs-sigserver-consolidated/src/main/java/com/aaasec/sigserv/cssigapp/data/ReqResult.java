/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.data;

import com.aaasec.sigserv.cscommon.enums.Enums;

/**
 *
 * @author stefan
 */
public class ReqResult {

    public String id;
    public String code;
    public String message;
    public String spUrl;
    public String idpEntityId;
    public String signServiceEntityId;
    public String errorResponse = "";

    public ReqResult(Enums.ResponseCodeMajor type, String id, String spUrl) {
        this.id = id;
        code = type.getCode();
        message = type.getMessage();
        this.spUrl = spUrl;
    }

    public ReqResult(Enums.ResponseCodeMajor type, String id, String spUrl, String message) {
        this.id = id;
        code = type.getCode();
        this.message = message;
        this.spUrl = spUrl;
    }

}
