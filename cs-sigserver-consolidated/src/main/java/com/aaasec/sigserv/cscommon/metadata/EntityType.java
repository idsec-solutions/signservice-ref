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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.w3c.dom.Node;
import x0Metadata.oasisNamesTcSAML2.AttributeAuthorityDescriptorType;
import x0Metadata.oasisNamesTcSAML2.AuthnAuthorityDescriptorType;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;
import x0Metadata.oasisNamesTcSAML2.IDPSSODescriptorType;
import x0Metadata.oasisNamesTcSAML2.PDPDescriptorType;
import x0Metadata.oasisNamesTcSAML2.RoleDescriptorType;
import x0Metadata.oasisNamesTcSAML2.SPSSODescriptorType;

/**
 * Metadata entity type enumeration
 */
public enum EntityType implements MetadataConstants {

    idp("IDPSSODescriptor", "Identity Provider"),
    sp("SPSSODescriptor", "Service Provider"),
    aa("AttributeAuthorityDescriptor", "Attribute Authority"),
    auth("AuthnAuthorityDescriptor", "Authentication Authority"),
    sign("SPSSODescriptor", "Signature Service"),
    pdp("PDPDescriptor", "Policy Decision Point"),
    role("RoleDescriptor", "Role");
    private String descriptorElement;
    private String entityTypeFriendlyName;

    private EntityType(String descriptorElement, String entityTypeFriendlyName) {
        this.descriptorElement = descriptorElement;
        this.entityTypeFriendlyName = entityTypeFriendlyName;
    }

    public String getDescriptorElement() {
        return descriptorElement;
    }

    public String getEntityTypeFriendlyName() {
        return entityTypeFriendlyName;
    }

    public static EntityType getEntityType(EntityDescriptorType ed) {
        return getEntityType(ed, new String[]{});
    }

    public static EntityType getEntityType(EntityDescriptorType ed, String[] signEntityIds) {
        List<EntityType> entityTypes = getEntityTypes(ed, signEntityIds);
        if (entityTypes.size() == 1) {
            return entityTypes.get(0);
        }
        if (entityTypes.isEmpty()) {
            return null;
        }
        if (entityTypes.contains(EntityType.sign)) {
            return EntityType.sign;
        }
        return null;
    }

    public static List<EntityType> getEntityTypes(EntityDescriptorType ed) {
        return getEntityTypes(ed, new String[]{});
    }

    public static List<EntityType> getEntityTypes(EntityDescriptorType ed, String[] signEntityIds) {
        List<EntityType> etList = new ArrayList<EntityType>();
        String entityID = null;
        try {
            entityID = ed.getEntityID();
            IDPSSODescriptorType[] idp = ed.getIDPSSODescriptorArray();
            SPSSODescriptorType[] sp = ed.getSPSSODescriptorArray();
            AttributeAuthorityDescriptorType[] aa = ed.getAttributeAuthorityDescriptorArray();
            AuthnAuthorityDescriptorType[] autha = ed.getAuthnAuthorityDescriptorArray();
            PDPDescriptorType[] pdp = ed.getPDPDescriptorArray();
            RoleDescriptorType[] role = ed.getRoleDescriptorArray();

            if (idp != null && idp.length > 0) {
                if (!etList.contains(EntityType.idp)) {
                    etList.add(EntityType.idp);
                }
            }
            if (sp != null && sp.length > 0) {
                if (!etList.contains(EntityType.sp)) {
                    etList.add(EntityType.sp);
                }
            }
            if (aa != null && aa.length > 0) {
                if (!etList.contains(EntityType.aa)) {
                    etList.add(EntityType.aa);
                }
            }
            if (autha != null && autha.length > 0) {
                if (!etList.contains(EntityType.auth)) {
                    etList.add(EntityType.auth);
                }
            }
            if (pdp != null && pdp.length > 0) {
                if (!etList.contains(EntityType.pdp)) {
                    etList.add(EntityType.pdp);
                }
            }
            if (role != null && role.length > 0) {
                if (!etList.contains(EntityType.role)) {
                    etList.add(EntityType.role);
                }
            }
        } catch (Exception ex) {
        }

        // Check if the service is a sign service
        boolean sigService = false;
        if (entityID != null && etList.contains(EntityType.sp)) {
            List<String> sigEidList = Arrays.asList(signEntityIds);
            if (sigEidList.contains(entityID)) {
                sigService = true;
            }
            try {
                //test
                if (entityID.equals("https://eid2csig.konki.se/sign")){
                    int jklsdf=0;
                }
                List<EntityAttributeVal> attrVals = MetaDataDoc.getEntityAttributes(ed).get(ENTITY_CATEGORY_ATTR_NAME);
                for (EntityAttributeVal attrVal : attrVals) {
                    if (attrVal.value.equalsIgnoreCase(SIG_SERVICE_ENTITY_CATEGORY) ||attrVal.value.equalsIgnoreCase(SIG_SERVICE_DEPR_ENTITY_CATEGORY) ) {
                        sigService = true;
                    }
                }
            } catch (Exception ex) {
            }

            if (sigService) {
                etList.add(EntityType.sign);
            }
        }


        return etList;
    }

    public static EntityType getEntityType(Node elementNode) {
        return getEntityType(elementNode.getNodeName(), elementNode.getNamespaceURI());
    }

    public static EntityType getEntityType(String elementName) {
        return getEntityType(elementName, SAML_METADATA_NS);
    }

    public static EntityType getEntityType(String elementName, String nameSpace) {
        if (elementName == null || nameSpace == null) {
            return null;
        }
        EntityType[] types = EntityType.values();
        for (EntityType type : types) {
            if (elementName.equalsIgnoreCase(type.getDescriptorElement()) && nameSpace.equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:metadata")) {
                switch (type) {
                    case sign:
                        return EntityType.sp;
                    default:
                        return type;
                }
            }
        }
        return null;
    }
}
