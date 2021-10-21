/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import java.util.List;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;

/**
 *
 * @author stefan
 */
public class ApConditions extends AbstractOpenSamlObj<Conditions>{

    public ApConditions() {
        super(Conditions.DEFAULT_ELEMENT_NAME);
    }

    public ApConditions(Conditions obj) {
        super(obj, Conditions.DEFAULT_ELEMENT_NAME);
    }
    
    public ApConditions setConditions(String requesterEntityId, int timeScewSec, int validitySec){
        obj.setNotBefore(new DateTime(System.currentTimeMillis()-timeScewSec*1000));
        obj.setNotOnOrAfter(new DateTime(System.currentTimeMillis()+validitySec*1000));
        List<AudienceRestriction> audienceRestrictions = obj.getAudienceRestrictions();        
        AudienceRestriction audRestr = Builder.audienceRestrictionBuilder.buildObject();
        audienceRestrictions.add(audRestr);
        List<Audience> audiences = audRestr.getAudiences();
        Audience audience = Builder.audienceBuilder.buildObject();
        audiences.add(audience);
        audience.setAudienceURI(requesterEntityId);
        return this;
    }
}
