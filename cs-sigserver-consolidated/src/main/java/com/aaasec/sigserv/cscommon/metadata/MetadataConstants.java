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
package com.aaasec.sigserv.cscommon.metadata;

/**
 * MD Validator constants.
 */
public interface MetadataConstants {
    static final String LF = System.getProperty("line.separator");
    static final String SERVLET_URL = "mdv";
    static final String OK_ICN = "img/Ok-icon.png";
    static final String NOK_ICN = "img/Nok-icon.png";
    static final String WARNING_ICN = "img/Warning-icon.png";
    static final String SAML_METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata";
    static final String SAML_META_ATTR_NS = "urn:oasis:names:tc:SAML:metadata:attribute";
    static final String SAML_MDUI_NS = "urn:oasis:names:tc:SAML:metadata:ui";
    static final String DISCOVERY_RESPONSE_NS = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol";
    static final String MDUI_ELEMENT = "UIInfo";
    static final String SAML_ATTRIBUTE_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    static final String ASSURANCE_CERTIFICATION_ATTR_NAME = "urn:oasis:names:tc:SAML:attribute:assurance-certification";
    static final String ENTITY_CATEGORY_ATTR_NAME = "http://macedir.org/entity-category";
    static final String SIG_SERVICE_ENTITY_CATEGORY = "http://id.elegnamnden.se/st/1.0/sigservice";
    static final String SIG_SERVICE_DEPR_ENTITY_CATEGORY = "http://id.elegnamnden.se/ec/1.0/sigservice";
    static final String ENTITY_DESCRIPTOR_ELEMENT = "EntityDescriptor";
    static final String ENTITY_ATTRIBUTE_ELEMENT = "EntityAttributes";
    static final String DISCOVERY_RESPONSE_ELEMENT = "DiscoveryResponse";
    static final String DISCO_BINDING = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol";
    
    static final String[] EID2_LOA_ARRAY = new String[]{"http://id.elegnamnden.se/loa/1.0/loa1","http://id.elegnamnden.se/loa/1.0/loa2","http://id.elegnamnden.se/loa/1.0/loa3","http://id.elegnamnden.se/loa/1.0/loa4"};
}
