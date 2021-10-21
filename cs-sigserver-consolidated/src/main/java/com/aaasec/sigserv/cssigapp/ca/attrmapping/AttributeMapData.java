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
package com.aaasec.sigserv.cssigapp.ca.attrmapping;

import se.elegnamnden.id.csig.x11.dssExt.ns.MappedAttributeType;
import se.elegnamnden.id.csig.x11.dssExt.ns.MappedAttributeType.CertNameType.Enum;

/**
 * Attribute mapping data.
 */
public class AttributeMapData {
    public String certRef;
    public MappedAttributeType.CertNameType.Enum certNameType;
    public boolean fromSamlAttribute;
    public String samlAttributeName;
    public String friendlyName;
    public String value;

    public AttributeMapData(String certRef, Enum certNameType, boolean fromSamlAttribute, String samlAttributeName, String friendlyName, String value) {
        this.certRef = certRef;
        this.certNameType = certNameType;
        this.fromSamlAttribute = fromSamlAttribute;
        this.samlAttributeName = samlAttributeName;
        this.friendlyName = friendlyName;
        this.value = value;
    }


    public AttributeMapData() {
    }
    
}
