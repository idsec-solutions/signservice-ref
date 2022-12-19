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

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
import com.aaasec.sigserv.cscommon.Base64Coder;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import oasisNamesTcSAMLMetadataUi.UIInfoType;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.w3.x2000.x09.xmldsig.X509DataType;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import x0Metadata.oasisNamesTcSAML2.EndpointType;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;
import x0Metadata.oasisNamesTcSAML2.IDPSSODescriptorType;
import x0Metadata.oasisNamesTcSAML2.KeyDescriptorType;
import x0Metadata.oasisNamesTcSAML2.KeyTypes;
import x0Metadata.oasisNamesTcSAML2.LocalizedNameType;
import x0Metadata.oasisNamesTcSAML2.SPSSODescriptorType;

/**
 * Class for parsing SAML Metadata.
 */
public final class UrlMetaDataSource extends CompleteMetaData {

    private Thread recacheThread;
    private long cacheInterval;
    private final static Logger LOG = Logger.getLogger(UrlMetaDataSource.class.getName());
    private com.aaasec.sigserv.cscommon.metadata.MetaDataDoc metadata;
    private String mdUrl;
    private X509Certificate metadataCert;
//    private RefreshUrlCache refUrlCache = new RefreshUrlCache();
    private static long lastRecache;

    public UrlMetaDataSource(String mdUrl, X509Certificate cert, int refreshMinutes) {
        this.mdUrl = mdUrl;
        this.metadataCert = cert;
        this.refreshMinutes = refreshMinutes;
        cacheInterval = (long) refreshMinutes * 1000 * 60;
        initMetadata();
    }

    private void initMetadata() {
        try {
            metadata = new com.aaasec.sigserv.cscommon.metadata.MetaDataDoc(mdUrl, metadataCert, new String[]{});
            if (metadata.isInitialized()) {
                initialized = true;
                entityDescriptorMap = extractEntityDescriptorMap(metadata.getMetadata());
                parseMetadata();
            }
        } catch (Exception ex) {
            LOG.warning("Unable to read and parse metadata source");
            LOG.log(Level.SEVERE, null, ex);
        }
    }

    protected void parseMetadata() {
        try {
            entityIds = new ArrayList<String>();
            nameMap = new HashMap<String, Map>();
            certMap = new HashMap<String, List<String>>();
            typeMap = new HashMap<String, EntityType>();
            idpSupportedClassRefMap = new HashMap<String, List<String>>();
            List<EntityDescriptorType> entityList = metadata.getEntityList();
            Map<String, List<MduiExtVal>> entityMduiMap = metadata.getEntityMduiMap();

            for (EntityDescriptorType ed : entityList) {
                String entityId = ed.getEntityID();
                entityIds.add(entityId);
                HashMap<String, String> idpDisplName = new HashMap<String, String>();

                //Get display name, primary from MDUI
                boolean hasMdui = false;
                if (entityMduiMap.containsKey(entityId)) {
                    List<MduiExtVal> mduiList = entityMduiMap.get(entityId);
                    if (!mduiList.isEmpty()) {
                        for (MduiExtVal mdui : mduiList) {
                            switch (mdui.entityType) {
                                case idp:
                                case sp:
                                    hasMdui = true;
                                    typeMap.put(entityId, mdui.entityType);
                                    UIInfoType uiInfo = mdui.mduiExt;
                                    LocalizedNameType[] displayNameArray = uiInfo.getDisplayNameArray();
                                    for (LocalizedNameType dispName : displayNameArray) {
                                        idpDisplName.put(dispName.getLang(), dispName.getStringValue());
                                    }
                            }
                        }
                        nameMap.put(entityId, idpDisplName);
                    }
                }
                if (!hasMdui) {
                    // in case this entity does not have any MDUI
                    try {
                        LocalizedNameType[] organizationDisplayNameArray = ed.getOrganization().getOrganizationDisplayNameArray();
                        for (LocalizedNameType dispName : organizationDisplayNameArray) {
                            idpDisplName.put(dispName.getLang(), dispName.getStringValue());
                        }
                        nameMap.put(entityId, idpDisplName);
                    } catch (Exception ex) {
                    }
                }
                //Get Cert
                try {
                    IDPSSODescriptorType[] idpssoDescriptorArray = ed.getIDPSSODescriptorArray();
                    if (idpssoDescriptorArray != null && idpssoDescriptorArray.length > 0) {
                        addCerts(idpssoDescriptorArray[0].getKeyDescriptorArray(), entityId);
                    }
                    SPSSODescriptorType[] spssoDescriptorArray = ed.getSPSSODescriptorArray();
                    if (spssoDescriptorArray != null && spssoDescriptorArray.length > 0) {
                        addCerts(spssoDescriptorArray[0].getKeyDescriptorArray(), entityId);
                    }
                } catch (Exception ex) {
                }
            }

            // Get SSO Map
            Map<EntityType, List<EntityDescriptorType>> entityTypeMap = metadata.getEntityTypeMap();
            if (entityTypeMap.containsKey(EntityType.idp)) {
                List<EntityDescriptorType> idpList = entityTypeMap.get(EntityType.idp);
                for (EntityDescriptorType ed : idpList) {
                    // Get SSO Map
                    try {
                        IDPSSODescriptorType idpssoDescriptor = ed.getIDPSSODescriptorArray(0);
                        EndpointType[] singleSignOnServiceArray = idpssoDescriptor.getSingleSignOnServiceArray();
                        Map<String, String> idpSsoMap = new HashMap<String, String>();
                        for (EndpointType ssos : singleSignOnServiceArray) {
                            String binding = ssos.getBinding();
                            String location = ssos.getLocation();
                            idpSsoMap.put(binding, location);
                        }
                        ssoMap.put(ed.getEntityID(), idpSsoMap);
                    } catch (Exception ex) {
                    }
                    // Get IdP supported context class refs
                    try {
                        Map<String, List<EntityAttributeVal>> entAttrMap = metadata.getEntityAttributeMap().get(ed.getEntityID());
                        if (entAttrMap.containsKey("urn:oasis:names:tc:SAML:attribute:assurance-certification")) {
                            List<String> classRefList = new ArrayList<String>();
                            List<EntityAttributeVal> attrValList = entAttrMap.get("urn:oasis:names:tc:SAML:attribute:assurance-certification");
                            for (EntityAttributeVal attrVal : attrValList) {
                                classRefList.add(attrVal.value.trim().toLowerCase());
                            }
                            idpSupportedClassRefMap.put(ed.getEntityID(), classRefList);
                        }
                    } catch (Exception ex) {
                    }
                }
            }

        } catch (Exception ex) {
        }
    }

    private void addCerts(KeyDescriptorType[] keyDescriptorArray, String entityId) {
        LOG.fine("Adding certificates for EntityId: " + entityId);
        int certCount = 0;
        for (KeyDescriptorType kd : keyDescriptorArray) {
            List<String> certList = certMap.containsKey(entityId) ? certMap.get(entityId) : new ArrayList<String>();
            KeyTypes.Enum use = kd.getUse();
            if (use == null || use.equals(KeyTypes.SIGNING)) {
                byte[] certBytes = getKeyDescriptorCertBytes(kd);
                certList.add(Base64Coder.encodeLines(certBytes));
                certMap.put(entityId, certList);
                certCount++;
            }

            if (use == null || use.equals(KeyTypes.ENCRYPTION)) {
                byte[] certBytes = getKeyDescriptorCertBytes(kd);
                encCertMap.put(entityId, Base64Coder.encodeLines(certBytes));
                certCount++;
            }
        }
        LOG.fine("Added " + certCount + " certificates");
    }

    private byte[] getKeyDescriptorCertBytes(KeyDescriptorType kd) {
        try {
            return kd.getKeyInfo().getX509DataArray(0).getX509CertificateArray(0);
        } catch (Exception ex) {
            LOG.fine("Unable to retrieve certificate from regular byte read from KeyDescriptor");
        }
        String elementRawText = "";
        try {
            X509DataType x509Data = kd.getKeyInfo().getX509DataArray(0);
            elementRawText = x509Data.toString();
            String recoveredRawB64 = parseRawElement(elementRawText);

            Node domNode = x509Data.getDomNode();
            final NodeList childNodes = domNode.getChildNodes();
            StringBuilder b = new StringBuilder();
            for (int i = 0; i<childNodes.getLength(); i++){
                Node childNode = childNodes.item(i);
                if (childNode.getNodeType() == Node.TEXT_NODE){
                    b.append(childNode.getNodeValue());
                }
            }
            String nodeValue = b.toString().trim();
            if (StringUtils.isNotBlank(nodeValue)){
                byte[] certBytes = Base64.decode(nodeValue);
                if (certBytes != null && certBytes.length >0) {
                    return certBytes;
                }
            }
            if (StringUtils.isNotBlank(recoveredRawB64)){
                byte[] certBytes = Base64.decode(recoveredRawB64);
                if (certBytes != null && certBytes.length >0) {
                    LOG.fine("Successfully recovered certificate bytes from XML parsing");
                    return certBytes;
                }
            }
        } catch (Exception ex) {
            LOG.fine("Failed to recover certificate bytes form digital identity: " + ex);
            return null;
        }
        LOG.fine("Failed to recover certificate bytes from key descriptor: \n" + elementRawText );
        return null;
    }

    private String parseRawElement(String elementRawText) {
        int certElementStartIdx = elementRawText.indexOf("X509Certificate");
        if (certElementStartIdx == -1) {
            return null;
        }
        String certElementData = elementRawText.substring(certElementStartIdx);

        int dataStartIdx = certElementData.indexOf(">");
        if (dataStartIdx == -1){
            return null;
        }
        String removeLeadingTag = certElementData.substring(dataStartIdx + 1);
        final int endIdx = removeLeadingTag.indexOf("<");
        return removeLeadingTag.substring(0, endIdx).trim();
    }

    public long getCacheInterval() {
        return cacheInterval;
    }
}
