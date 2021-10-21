/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cscommon.enums;

/**
 *
 * @author stefan
 */
public enum ContextAttributes {
    identityProvider("Identity-Provider"),
    authContextClass("Authentication-Method"),
    authInstant("Authentication-Instant"),
    assertionId("Assertion-ID");
    
    String attrName;

    private ContextAttributes(String attrName) {
        this.attrName = attrName;
    }

    public String getAttrName() {
        return attrName;
    }
    
    public static ContextAttributes getContextAttributeByName (String name){
        for (ContextAttributes attr:values()){
            if (name.equalsIgnoreCase(attr.getAttrName())){
                return attr;
            }
        }
        return null;
    }
    
}
