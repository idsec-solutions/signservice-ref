/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cscommon.enums;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author stefan
 */
public enum SamlAttribute {

    cn("urn:oid:2.5.4.3"),
    sn("urn:oid:2.5.4.4"),
    givenName("urn:oid:2.5.4.42"),
    mail("urn:oid:0.9.2342.19200300.100.1.3"),
    telephoneNumber("urn:oid:2.5.4.20"),
    title("urn:oid:2.5.4.12"),
    initials("urn:oid:2.5.4.43)"),
    description("urn:oid:2.5.4.13"),
    departmentNumber("urn:oid:2.16.840.1.113730.3.1.2"),
    employeeNumber("urn:oid:2.16.840.1.113730.3.1.3"),
    employeeType("urn:oid:2.16.840.1.113730.3.1.4"),
    preferredLanguage("urn:oid:2.16.840.1.113730.3.1.39"),
    displayName("urn:oid:2.16.840.1.113730.3.1.241"),
    street("urn:oid:2.5.4.9"),
    postOfficeBox("urn:oid:2.5.4.18"),
    postalCode("urn:oid:2.5.4.17"),
    st("urn:oid:2.5.4.8"),
    l("urn:oid:2.5.4.7"),
    country("urn:oid:2.5.4.6"),
    o("urn:oid:2.5.4.10"),
    ou("urn:oid:2.5.4.11"),
    norEduPersonNIN("urn:oid:1.3.6.1.4.1.2428.90.1.5"),
    mobileTelephoneNumber("urn:oid:0.9.2342.19200300.100.1.41"),
    personalIdentityNumber("urn:oid:1.2.752.29.4.13"),
    persistentId("urn:oid:1.3.6.1.4.1.5923.1.1.1.10"),
    dateOfBirth("http://www.stork.gov.eu/1.0/dateOfBirth"),
    eIdentifier("http://www.stork.gov.eu/1.0/eIdentifier"),
    gender("http://www.stork.gov.eu/1.0/gender"),
    provisionalIdLeg("urn:oid:1.3.6.1.4.1.40169.2.1"),
    pidQualityLeg("urn:oid:1.3.6.1.4.1.40169.2.2"),
    provisionalId("urn:oid:1.2.752.201.3.4"),
    pidQuality("urn:oid:1.2.752.201.3.5"),
    orgAffiliation("urn:oid:1.2.752.201.3.1"),
    sad("urn:oid:1.2.752.201.3.12"),
    affiliation("urn:oid:1.3.6.1.4.1.5923.1.1.1.9"),
    eppn("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"),
    eduPersonAssurance("urn:oid:1.3.6.1.4.1.5923.1.1.1.11"),
    eIDASPersonIdentifier("urn:oid:1.2.752.201.3.7");

    String samlName;

    private SamlAttribute(String samlName) {
        this.samlName = samlName;
    }

    public String getSamlName() {
        return samlName;
    }

    public static SamlAttribute getAttributeFromSamlName(String samlName) {
        for (SamlAttribute attr : values()) {
            if (attr.getSamlName().equalsIgnoreCase(samlName)) {
                return attr;
            }
        }
        return null;
    }

    public static List<SamlAttribute> getIdAttributes() {
        List<SamlAttribute> attrList = new ArrayList<SamlAttribute>();
        attrList.add(personalIdentityNumber);
        attrList.add(provisionalId);
        attrList.add(provisionalIdLeg);
        attrList.add(sad);
        attrList.add(eppn);
        attrList.add(eIDASPersonIdentifier);
        
        return attrList;
    }
    
    public static List<SamlAttribute> getDisplayNamedAttributes() {
        List<SamlAttribute> attrList = new ArrayList<SamlAttribute>();
        attrList.add(displayName);
        attrList.add(cn);        
        return attrList;
    }
    
    

}
