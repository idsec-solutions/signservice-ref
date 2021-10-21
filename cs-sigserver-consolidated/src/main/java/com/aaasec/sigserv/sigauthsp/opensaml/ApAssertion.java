/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import java.util.List;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Element;

/**
 *
 * @author stefan
 */
public class ApAssertion extends AbstractOpenSamlObj<Assertion>{

    public ApAssertion() {
        super(Assertion.DEFAULT_ELEMENT_NAME);
        obj.setID(getNewID());
        obj.setIssueInstant(new DateTime());
        obj.setVersion(SAMLVersion.VERSION_20);
    }

    public ApAssertion(Assertion obj) {
        super(obj, Assertion.DEFAULT_ELEMENT_NAME);
    }

    public void setIssuer(String issuerEntityId) {
        ApIssuer issuer = new ApIssuer();
        issuer.setIssuerEntityId(issuerEntityId);
        obj.setIssuer(issuer.obj);
    }
    
    public ApAttributeStatement addNewAttributeStatement(){
        List<AttributeStatement> attributeStatements = obj.getAttributeStatements();
        ApAttributeStatement attrStatement = new ApAttributeStatement();
        attributeStatements.add(attrStatement.obj);
        return attrStatement;        
    }
    
    public void setSubject (Subject subject) throws MarshallingException, UnmarshallingException{
        Marshaller marshaller = Builder.marshallerFactory.getMarshaller(subject);
        Element marshall = marshaller.marshall(subject);
        Unmarshaller unmarshaller = Builder.unmarshallerFactory.getUnmarshaller(marshall);
        Subject newSubject = (Subject) unmarshaller.unmarshall(marshall);        
        obj.setSubject(newSubject);        
    }

    public void setCondition(Issuer issuer, int timeScewSec, int validitySec) {
        ApConditions conditions = new ApConditions();
        conditions.setConditions(issuer.getValue(), timeScewSec, validitySec);
        obj.setConditions(conditions.obj);
    }
    
}
