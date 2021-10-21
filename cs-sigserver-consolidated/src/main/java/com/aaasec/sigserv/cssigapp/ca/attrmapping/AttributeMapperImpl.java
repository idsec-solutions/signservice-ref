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
import com.aaasec.sigserv.cscommon.enums.Enums;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.Name;
import iaik.x509.extensions.SubjectAltName;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.xmlbeans.XmlString;
import se.elegnamnden.id.authCont.x10.saci.AttributeMappingType;
import se.elegnamnden.id.authCont.x10.saci.AuthContextInfoType;
import se.elegnamnden.id.authCont.x10.saci.IdAttributesType;
import se.elegnamnden.id.authCont.x10.saci.SAMLAuthContextDocument;
import se.elegnamnden.id.authCont.x10.saci.SAMLAuthContextType;
import se.elegnamnden.id.csig.x11.dssExt.ns.MappedAttributeType;
import se.elegnamnden.id.csig.x11.dssExt.ns.MappedAttributeType.CertNameType;
import se.elegnamnden.id.csig.x11.dssExt.ns.MappedAttributeType.CertNameType.Enum;
import se.elegnamnden.id.csig.x11.dssExt.ns.PreferredSAMLAttributeNameType;
import se.elegnamnden.id.csig.x11.dssExt.ns.RequestedAttributesType;
import x0Assertion.oasisNamesTcSAML2.AttributeType;

/**
 * Implementation of the attribute mapper interface
 */
public class AttributeMapperImpl implements AttributeMapper {

    static final String[] minimalSet = new String[]{ObjectID.serialNumber.getID(), ObjectID.surName.getID(), ObjectID.givenName.getID(), ObjectID.country.getID()};
    static final Map<String, List<String>> allowDefaultMap = new HashMap<String, List<String>>();
    static final Map<String, String> samlAttrNameMap = new HashMap<String, String>();
    private SubjectAltName sanExtension;
    private AttributeMapData sanAttrData = null;
    private String assertionRef = null;

    static {
        allowDefaultMap.put(ObjectID.country.getID(), Arrays.asList(new String[]{"SE"}));
        Set<String> keySet = Enums.idAttributes.keySet();
        for (String key : keySet) {
            samlAttrNameMap.put("urn:oid:" + Enums.idAttributes.get(key), key);
        }
    }

    public Name getSubjectName(RequestedAttributesType requestedAttributes, AuthData user) {
        attributeMap.clear();
        attributeOidList.clear();
        Name subject = new Name();
        if (requestedAttributes == null) {
            return getDefaultSubjectName(user);
        }
        //Get user assertion ref
        try {
            assertionRef = user.getAssertioinDocument(0).getAssertion().getID();
        } catch (Exception ex) {
        }


        MappedAttributeType[] reqAttrArray = requestedAttributes.getRequestedCertAttributeArray();
        for (MappedAttributeType reqAttr : reqAttrArray) {
            /* 
             * Get the mapped attributes for a given requested attribute.
             * Return null subject if status false is received.
             * This means that a value was required but no one could be found.
             */
            if (!getAttributeMapFromReqAttr(subject, reqAttr, user)) {
                return null;
            }
        }

        // check that all CA required attributes are resolved.
        for (String reqOid : minimalSet) {
            if (!attributeOidList.contains(reqOid)) {
                return null;
            }
        }
        return subject;
    }

    public Map<String, AttributeMapData> getAttributeMap() {
        return attributeMap;
    }

    private static boolean addNameRdn(Name subject, ObjectID oid, AttributeMapData attrMapData) {
        if (attrMapData == null) {
            return false;
        }
        attrMapData.certRef = oid.getID();
        // If a value has been set
        if (attrMapData.value.length() > 0) {
            // If the value was a default value, check that the default value is allowed
            if (!attrMapData.fromSamlAttribute) {
                String defVal = attrMapData.value;
                boolean allowed = false;
                if (allowDefaultMap.containsKey(oid.getID())) {
                    List<String> allowedValues = allowDefaultMap.get(oid.getID());
                    if (allowedValues.contains(defVal)) {
                        allowed = true;
                    }
                }
                // if an illegal default value was provided, reject cert request.
                if (!allowed) {
                    return false;
                }
            }

            //Add the subject attribute
            subject.addRDN(oid, attrMapData.value);
            attributeMap.put(oid.getID(), attrMapData);
            attributeOidList.add(oid.getID());
            return true;
        }
        // No value was added.
        return false;
    }

    private static AttributeMapData getAttributeMapData(String friendlyName, AuthData user, String attribute, String defaultVal) {
        return getAttributeMapData(friendlyName, user, new String[]{attribute}, defaultVal, CertNameType.RDN);
    }

    private static AttributeMapData getAttributeMapData(String friendlyName, AuthData user, String[] attributes, String defaultVal) {
        return getAttributeMapData(friendlyName, user, attributes, defaultVal, CertNameType.RDN);
    }

    private static AttributeMapData getAttributeMapData(String friendlyName, AuthData user, String[] attributes, String defaultVal, CertNameType.Enum certNameType) {
        List<List<String>> userAttr = user.getAttribute();
        AttributeMapData attrMapData = new AttributeMapData();
        attrMapData.friendlyName = friendlyName;
        attrMapData.certNameType = certNameType;

        for (String matchAttr : attributes) {
            for (List<String> attr : userAttr) {
                try {
                    if (attr.get(0).equals(matchAttr)) {
                        attrMapData.friendlyName = attr.get(1);
                        attrMapData.fromSamlAttribute = true;
                        attrMapData.samlAttributeName = "urn:oid:" + Enums.idAttributes.get(attr.get(0));
                        attrMapData.value = attr.get(2);
                        return attrMapData;
                    }
                } catch (Exception ex) {
                }
            }
        }
        // no match check for default value
        if (defaultVal != null) {
            attrMapData.fromSamlAttribute = false;
            attrMapData.samlAttributeName = null;
            attrMapData.value = defaultVal;
            return attrMapData;
        }
        return null;

    }

    private boolean getAttributeMapFromReqAttr(Name subject, MappedAttributeType reqAttr, AuthData user) {
        String oidId = reqAttr.getCertAttributeRef();
        oidId = oidId.toLowerCase().startsWith("urn:oid:") ? oidId.substring(8) : oidId;
        CertNameType.Enum certNameType = reqAttr.getCertNameType();
        boolean san = false;
        ObjectID oid = null;
        if (certNameType != null && certNameType.equals(CertNameType.SAN)) {
            // This means that the requested attribute is supposed to go into a SAN.
            // To be dealt with later. Pass for now.
            san = true;
        } else {
            oid = new ObjectID(oidId);
        }
        PreferredSAMLAttributeNameType[] samlAttributeNameArray = reqAttr.getSamlAttributeNameArray();
        if (samlAttributeNameArray == null) {
            return false;
        }

        // Get the key names from the oid names
        int len = samlAttributeNameArray.length;
        String[] samlAttrNameKeys = new String[len], orderedSamlAttrNameKeys = new String[len];
        int[] order = new int[len];
        int idx = 0;
        for (PreferredSAMLAttributeNameType attrName : samlAttributeNameArray) {
            if (samlAttrNameMap.containsKey(attrName.getStringValue())) {
                samlAttrNameKeys[idx] = samlAttrNameMap.get(attrName.getStringValue());
                order[idx++] = attrName.getOrder();
            }
        }
        orderedSamlAttrNameKeys = getOrderedAttrNames(samlAttrNameKeys, order);

        boolean added = false;
        AttributeMapData attributeMapData = getAttributeMapData(reqAttr.getFriendlyName(), user, orderedSamlAttrNameKeys, reqAttr.getDefaultValue(), reqAttr.getCertNameType());
        if (san) {
            added = addSubjAltName(subject, oidId, attributeMapData);
        } else {
            added = addNameRdn(subject, oid, attributeMapData);
        }

        if (reqAttr.getRequired() && !added) {
            return false;
        }
        return true;
    }

    private Name getDefaultSubjectName(AuthData user) {
        Name subject = new Name();
        addNameRdn(subject, ObjectID.country, getAttributeMapData("Country", user, "country", "SE"));
        addNameRdn(subject, ObjectID.serialNumber, getAttributeMapData("Swedish personnummer", user, new String[]{"personalIdentityNumber", "mail"}, null));
        addNameRdn(subject, ObjectID.commonName, getAttributeMapData("Common name", user, new String[]{"cn", "displayName"}, null));
        addNameRdn(subject, ObjectID.surName, getAttributeMapData("Surename", user, "sn", null));
        addNameRdn(subject, ObjectID.givenName, getAttributeMapData("Given Name", user, "givenName", null));
        return subject;
    }

    public SAMLAuthContextDocument getSamlAssertionInfo(SAMLAuthContextDocument simpleAssertionInfo) {
        if (attributeOidList.isEmpty()) {
            return simpleAssertionInfo;
        }
        SAMLAuthContextType samlAuthContext = simpleAssertionInfo.getSAMLAuthContext();
        IdAttributesType idAttributes = IdAttributesType.Factory.newInstance();
        for (String oid : attributeOidList) {
            AttributeMapData amd = attributeMap.get(oid);
            if (amd.fromSamlAttribute) {
                AttributeMappingType attrMap = idAttributes.addNewAttributeMapping();
                AttributeType samlAttr = attrMap.addNewAttribute();
                XmlString attrVal = XmlString.Factory.newInstance();
                attrVal.setStringValue(amd.value);
                XmlString[] valArray = new XmlString[]{attrVal};
                samlAttr.setAttributeValueArray(valArray);
                samlAttr.setFriendlyName(amd.friendlyName);
                samlAttr.setName(amd.samlAttributeName);
                attrMap.setType(getCertNameType(amd.certNameType));
                attrMap.setRef(oid);
//                simpleAssertionInfo.addIdAttribute(amd.friendlyName, amd.samlAttributeName, amd.value, getCertNameType(amd.certNameType), oid);
            }
        }
        if (sanAttrData != null) {
            AttributeMappingType attrMap = idAttributes.addNewAttributeMapping();
            AttributeType samlAttr = attrMap.addNewAttribute();
            XmlString attrVal = XmlString.Factory.newInstance();
            attrVal.setStringValue(sanAttrData.value);
            XmlString[] valArray = new XmlString[]{attrVal};
            samlAttr.setAttributeValueArray(valArray);
            samlAttr.setFriendlyName(sanAttrData.friendlyName);
            samlAttr.setName(sanAttrData.samlAttributeName);
            attrMap.setType(getCertNameType(sanAttrData.certNameType));
            attrMap.setRef(sanAttrData.certRef);
        }

        //Insert assertion ref
        if (assertionRef != null) {
            AuthContextInfoType authContextInfo = samlAuthContext.getAuthContextInfo();
            authContextInfo.setAssertionRef(assertionRef);
        }

        samlAuthContext.setIdAttributes(idAttributes);
        return simpleAssertionInfo;
    }

    private String[] getOrderedAttrNames(String[] samlAttrNameKeys, int[] order) {
        int len = samlAttrNameKeys.length;
        if (len != order.length) {
            return null;
        }

        int[] sortedOrders = Arrays.copyOf(order, len);
        Arrays.sort(sortedOrders);
        ArrayList<String> picked = new ArrayList<String>();

        for (int i = 0; i < len; i++) {
            int currentOrder = sortedOrders[i];
            for (int j = 0; j < len; j++) {
                if (order[j] == currentOrder) {
                    if (!picked.contains(samlAttrNameKeys[j])) {
                        picked.add(samlAttrNameKeys[j]);
                    }
                }
            }
        }

        return picked.toArray(new String[]{});
    }

    public SubjectAltName getSubjectAltNameExtension() {
        return sanExtension;
    }

    private boolean addSubjAltName(Name subject, String certRef, AttributeMapData attrMapData) {
        if (certRef == null || attrMapData == null || attrMapData.value == null) {
            return false;
        }
        if (certRef.trim().equals("1")) {
            attrMapData.certRef = certRef;
            // If a value has been set
            if (attrMapData.value.length() > 0) {
                // If the value was a default value, don't allow this for e-mails.
                if (!attrMapData.fromSamlAttribute) {
                    return false;
                }

                //Add the subject alt name ext.
                SubjectAltName san = new SubjectAltName();
                GeneralName gname = new GeneralName(1, attrMapData.value);
                GeneralNames gnames = new GeneralNames(gname);
                san.setGeneralNames(gnames);
                sanExtension = san;
                sanAttrData = attrMapData;
                return true;
            }
        }
        // No value was added.
        return false;

    }

    private AttributeMappingType.Type.Enum getCertNameType(Enum certNameType) {
        AttributeMappingType.Type.Enum cnt = AttributeMappingType.Type.RDN;
        try {
            cnt = AttributeMappingType.Type.Enum.forString(certNameType.toString());
        } catch (Exception ex) {
        }
        return cnt;
    }
}
