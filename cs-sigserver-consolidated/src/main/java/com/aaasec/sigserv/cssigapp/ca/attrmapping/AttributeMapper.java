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

import com.aaasec.sigserv.cscommon.data.AuthData;
import iaik.asn1.structures.Name;
import iaik.x509.extensions.SubjectAltName;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import se.elegnamnden.id.authCont.x10.saci.SAMLAuthContextDocument;
import se.elegnamnden.id.csig.x11.dssExt.ns.RequestedAttributesType;

/**
 * Attribute mapper interface.
 */
public interface AttributeMapper {
    Map<String,AttributeMapData> attributeMap = new HashMap<String, AttributeMapData>();
    List<String> attributeOidList = new ArrayList<String>();

    public Name getSubjectName(RequestedAttributesType requestedAttributes, AuthData user);
    public Map<String,AttributeMapData> getAttributeMap();

    public SAMLAuthContextDocument getSamlAssertionInfo(SAMLAuthContextDocument simpleAssertionInfo);
    public SubjectAltName getSubjectAltNameExtension();
}
