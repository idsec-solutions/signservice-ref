/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import java.util.List;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSString;
import org.w3c.dom.Element;

/**
 *
 * @author stefan
 */
public class ApAttributeStatement extends AbstractOpenSamlObj<AttributeStatement>{

    public ApAttributeStatement() {
        super(AttributeStatement.DEFAULT_ELEMENT_NAME);
    }

    public ApAttributeStatement(AttributeStatement obj) {
        super(obj, AttributeStatement.DEFAULT_ELEMENT_NAME);
    }
    
    public ApAttributeStatement addAttribute(Attribute attribute) throws MarshallingException, UnmarshallingException{
        Marshaller marshaller = Builder.marshallerFactory.getMarshaller(attribute);
        Element marshall = marshaller.marshall(attribute);
        Unmarshaller unmarshaller = Builder.unmarshallerFactory.getUnmarshaller(marshall);
        Attribute newAttribute = (Attribute) unmarshaller.unmarshall(marshall);
        
        List<Attribute> attributes = obj.getAttributes();
        attributes.add(newAttribute);
        return this;
    }
    
    public ApAttributeStatement addAttributeWithValue(String name, String friendlyName, String attrStringValue){
        Attribute attribute = Builder.attributeBuilder.buildObject();
        attribute.setName(name);
        attribute.setFriendlyName(friendlyName);
        XSString stringValue = Builder.xsStringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        stringValue.setValue(attrStringValue);
        attribute.getAttributeValues().add(stringValue);
        obj.getAttributes().add(attribute);
        return this;
    }
}
