/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;

/**
 *
 * @author stefan
 */
public class ApStatus extends AbstractOpenSamlObj<Status>{

    public ApStatus() {
        super(Status.DEFAULT_ELEMENT_NAME);
    }

    public ApStatus(Status obj) {
        super(obj, Status.DEFAULT_ELEMENT_NAME);
    }    
    
    
    public ApStatus setStatusCode(SamlStatusCode statusCode){
        StatusCode code = Builder.statusCodeBuilder.buildObject();
        code.setValue(statusCode.getUri());
        obj.setStatusCode(code);
        return this;
    }
    public ApStatus setStatusCode(SamlStatusCode statusCode, SamlStatusCode secondLevelStatus){
        StatusCode code = Builder.statusCodeBuilder.buildObject();
        code.setValue(statusCode.getUri());
        StatusCode secondCode = Builder.statusCodeBuilder.buildObject();
        secondCode.setValue(secondLevelStatus.getUri());
        code.setStatusCode(secondCode);
        obj.setStatusCode(code);
        return this;
    }
    
    public ApStatus setStatusMessage(String statusMessage){
        StatusMessage message = Builder.statusMessageBuilder.buildObject();
        message.setMessage(statusMessage);
        obj.setStatusMessage(message);
        return this;
    }    
}
