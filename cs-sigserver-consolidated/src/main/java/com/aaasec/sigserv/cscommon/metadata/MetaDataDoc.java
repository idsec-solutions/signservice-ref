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

import com.aaasec.lib.crypto.xml.SigVerifyResult;
import com.aaasec.lib.crypto.xml.XmlUtils;
import com.aaasec.sigserv.cscommon.DerefUrl;
import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import oasisNamesTcSAMLMetadataAttribute.EntityAttributesDocument;
import oasisNamesTcSAMLMetadataAttribute.EntityAttributesType;
import oasisNamesTcSAMLMetadataUi.UIInfoDocument;
import oasisNamesTcSAMLMetadataUi.UIInfoType;
import oasisNamesTcSAMLProfilesSSOIdpDiscoveryProtocol.DiscoveryResponseDocument;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;
import org.apache.xmlbeans.impl.values.XmlAnyTypeImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0Metadata.oasisNamesTcSAML2.EntitiesDescriptorDocument;
import x0Metadata.oasisNamesTcSAML2.EntitiesDescriptorType;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorDocument;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;
import x0Metadata.oasisNamesTcSAML2.ExtensionsType;
import x0Metadata.oasisNamesTcSAML2.IDPSSODescriptorType;
import x0Metadata.oasisNamesTcSAML2.IndexedEndpointType;
import x0Metadata.oasisNamesTcSAML2.LocalizedNameType;
import x0Metadata.oasisNamesTcSAML2.SPSSODescriptorType;

/**
 * Metadata object
 */
public final class MetaDataDoc implements MetadataConstants {

    private final static Logger LOG = Logger.getLogger(MetaDataDoc.class.getName());
    private EntitiesDescriptorDocument metadataDoc;
    private Document metadata;
    private boolean initialized;
    private long created = System.currentTimeMillis();
    private SigVerifyResult sigVerifyResult;
    private boolean sigPkMatch;
    private boolean sigIdAttributeVerified;
    private X509Certificate verifyCert;
    private List<EntityDescriptorType> entityList = new ArrayList<EntityDescriptorType>();
    private Map<EntityType, List<EntityDescriptorType>> entityTypeMap = new EnumMap<EntityType, List<EntityDescriptorType>>(EntityType.class);
    private Map<String, Map<String, List<EntityAttributeVal>>> entityAttributeMap = new HashMap<String, Map<String, List<EntityAttributeVal>>>();
    private Map<String, List<MduiExtVal>> entityMduiMap = new HashMap<String, List<MduiExtVal>>();
    private Map<String, EntityDescriptorType> entityMap = new HashMap<String, EntityDescriptorType>();
    private String[] sigServiceEntityId;
    private MdSchemaValid overallSchemaValid;
    private Map<String, MdSchemaValid> entitySchemaMap = new HashMap<String, MdSchemaValid>();
    private Map<String, IdpDiscoVal> discoLocationsMap = new HashMap<String, IdpDiscoVal>();

    public MetaDataDoc(InputStream is, X509Certificate verifyCert, String[] sigServiceEntityId) {
        this.verifyCert = verifyCert;
        this.sigServiceEntityId = sigServiceEntityId == null ? new String[]{} : sigServiceEntityId;
        initialized = false;
        try {
            metadataDoc = EntitiesDescriptorDocument.Factory.parse(is);
            metadata = getDocument(XmlBeansUtil.getBytes(metadataDoc));
            getEntities();
            initialized = true;
            verifySignature();
        } catch (Exception ex) {


            Logger.getLogger(MetaDataDoc.class.getName()).warning(ex.getMessage());
        }
    }

    public MetaDataDoc(String url, X509Certificate verifyCert, String[] sigServiceEntityId) {        
        this(new ByteArrayInputStream(DerefUrl.getBytes(url, DerefUrl.SslSecurityPolicy.SYSTEM_DEF)), verifyCert, sigServiceEntityId);
    }

    /**
     * Creates new metadata using original input metadata as base and adding or
     * replacing uploaded EntityDescriptors
     *
     * @param orgmd Original metadata, used as base
     * @param uploadedEntityDescriptors Uploaded metadata
     */
    public MetaDataDoc(MetaDataDoc orgmd, List<EntityDescriptorType> uploadedEntityDescriptors) {
        this.verifyCert = orgmd.getVerifyCert();
        this.sigServiceEntityId = orgmd.getSigServiceEntityId();
        initialized = false;
        try {
            // Clone original metadata
            metadataDoc = EntitiesDescriptorDocument.Factory.parse(orgmd.getMetadata());
            metadata = getDocument(XmlBeansUtil.getBytes(metadataDoc));
            // Verify signature on original metadata
            verifySignature();
            // Add or replace new uploaded EntityDescriptors
            addUploadedEntityDescriptors(uploadedEntityDescriptors);
            metadata = getDocument(XmlBeansUtil.getBytes(metadataDoc));
            getEntities();
            initialized = true;
        } catch (Exception ex) {
            Logger.getLogger(MetaDataDoc.class.getName()).warning(ex.getMessage());
        }
    }
    
    private static URL getUrl(String urlStr){
        try {
            URL url = new URL(urlStr);
            return url;
        } catch (MalformedURLException ex) {
            return null;
        }
    }

    private void verifySignature() {
        try {
            String iD = metadataDoc.getEntitiesDescriptor().getID();
            byte[] metadataBytes = XmlBeansUtil.getBytes(metadataDoc);
            sigVerifyResult = MdXmlDsig.verifySignatureID(metadataBytes, iD);
            sigIdAttributeVerified = true;
            if (!sigVerifyResult.valid) {
                sigIdAttributeVerified = false;
                sigVerifyResult = MdXmlDsig.verifySameDocRefSignature(metadataBytes);
            }
            sigPkMatch = checkPkMatch();
        } catch (Exception ex) {
        }
    }

    private boolean checkPkMatch() {
        if (verifyCert == null || sigVerifyResult == null || sigVerifyResult.cert == null) {
            return false;
        }
        X509Certificate sigCert = sigVerifyResult.cert;
        if (sigCert.getPublicKey().equals(verifyCert.getPublicKey())) {
            return true;
        }
        return false;
    }

    private static Document getDocument(byte[] docBytes) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document doc = dbFactory.newDocumentBuilder().parse(new ByteArrayInputStream(docBytes));
        return doc;
    }

    private void getEntities() {
        NodeList edNodes = metadata.getElementsByTagNameNS(SAML_METADATA_NS, ENTITY_DESCRIPTOR_ELEMENT);
        String updMD = XmlUtils.getDocText(metadata);
        entityList.clear();
        entityTypeMap.clear();
        entityMap.clear();
        for (int i = 0; i < edNodes.getLength(); i++) {
            Node edNode = edNodes.item(i);
            try {
                EntityDescriptorType ed = EntityDescriptorDocument.Factory.parse(edNode).getEntityDescriptor();
                String entityId = ed.getEntityID();
                if (entityId != null) {
                    // Add entity to list
                    entityList.add(ed);
                    entityMap.put(entityId, ed);
                    // Validate entity descriptor schema
                    updateSchemaValid(entityId, SchemaType.entityDescr, ed.validate());
                    // Add to entity type map;
                    List<EntityType> etList = EntityType.getEntityTypes(ed, sigServiceEntityId);
                    for (EntityType et : etList) {
                        List<EntityDescriptorType> edList = (entityTypeMap.containsKey(et)) ? entityTypeMap.get(et) : new ArrayList<EntityDescriptorType>();
                        edList.add(ed);
                        entityTypeMap.put(et, edList);
                    }
                    // Add to entity attribute map
                    entityAttributeMap.put(entityId, getEntityAttributes(ed));
                    validateEntityAttributeExtensions(ed);

                    // Add to mdui map
                    entityMduiMap.put(entityId, getAllMduiExtVals(ed));

                    // Add disco location map
                    addDiscoLocations(ed);

                }
            } catch (Exception ex) {
            }
        }
        updateDocSchemaValid();
    }

    private void validateEntityAttributeExtensions(EntityDescriptorType ed) {
        NodeList exNodes;
        try {
            ExtensionsType extensions = ed.getExtensions();
            exNodes = extensions.getDomNode().getChildNodes();
        } catch (Exception ex) {
            return;
        }
        for (int i = 0; i < exNodes.getLength(); i++) {
            try {
                Node ext = exNodes.item(i);
                if (ext.getNodeName().endsWith(ENTITY_ATTRIBUTE_ELEMENT) && ext.getNamespaceURI().equals(SAML_META_ATTR_NS)) {
                    EntityAttributesType extType = EntityAttributesDocument.Factory.parse(ext).getEntityAttributes();
                    updateSchemaValid(ed.getEntityID(), SchemaType.entityAttr, extType.validate());
                }
            } catch (Exception ex) {
            }
        }

    }

    /**
     * Collects EntityAttributes from a particular EntityDesciptor.
     *
     * @param ed An EntityDescriptor element
     * @return A map keyed by attribute name, providing a list of attribute
     * values for each name.
     */
    public static Map<String, List<EntityAttributeVal>> getEntityAttributes(EntityDescriptorType ed) {
        Map<String, List<EntityAttributeVal>> entAttributeMap = new HashMap<String, List<EntityAttributeVal>>();
        NodeList exNodes;
        try {
            ExtensionsType extensions = ed.getExtensions();
            exNodes = extensions.getDomNode().getChildNodes();
        } catch (Exception ex) {
            return entAttributeMap;
        }
        for (int i = 0; i < exNodes.getLength(); i++) {
            try {
                Node ext = exNodes.item(i);
                if (ext.getNodeName().endsWith(ENTITY_ATTRIBUTE_ELEMENT) && ext.getNamespaceURI().equals(SAML_META_ATTR_NS)) {
                    EntityAttributesType extType = EntityAttributesDocument.Factory.parse(ext).getEntityAttributes();
                    AttributeType[] attributeArray = extType.getAttributeArray();
                    for (AttributeType attr : attributeArray) {
                        String nameFormat = attr.getNameFormat();
                        String attrName = attr.getName();
                        if (nameFormat != null && attrName != null) {
                            for (XmlObject attrVal : attr.getAttributeValueArray()) {
                                if (attrVal instanceof XmlString) {
                                    String value = ((XmlString) attrVal).getStringValue();
                                    if (value != null) {
                                        List<EntityAttributeVal> valList = entAttributeMap.containsKey(attrName) ? entAttributeMap.get(attrName) : new ArrayList<EntityAttributeVal>();
                                        valList.add(new EntityAttributeVal(nameFormat, attrName, value));
                                        entAttributeMap.put(attrName, valList);
                                    }
                                }
                                if (attrVal instanceof XmlAnyTypeImpl) {
                                    String value = ((XmlAnyTypeImpl) attrVal).getStringValue();
                                    if (value != null) {
                                        List<EntityAttributeVal> valList = entAttributeMap.containsKey(attrName) ? entAttributeMap.get(attrName) : new ArrayList<EntityAttributeVal>();
                                        valList.add(new EntityAttributeVal(nameFormat, attrName, value));
                                        entAttributeMap.put(attrName, valList);
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (Exception ex) {
            }
        }
        return entAttributeMap;
    }

    /**
     * Collects all MDUI extensions from an EntityDescriptor
     *
     * @param ed An EntityDescriptor being searched for MDUI extensions
     * @return A List of MDUI extensions, each containing information about what
     * type of role descriptor that held the extension.
     */
    public List<MduiExtVal> getAllMduiExtVals(EntityDescriptorType ed) {
        List<MduiExtVal> mduiList = new ArrayList<MduiExtVal>();
        IDPSSODescriptorType[] idpArray = ed.getIDPSSODescriptorArray();
        SPSSODescriptorType[] spArray = ed.getSPSSODescriptorArray();

        if (idpArray != null && idpArray.length > 0) {
            List<UIInfoType> mduiExtensions = getMduiExtensions(idpArray[0].getExtensions());
            for (UIInfoType mdui : mduiExtensions) {
                mduiList.add(new MduiExtVal(EntityType.idp, mdui));
                updateSchemaValid(ed.getEntityID(), SchemaType.mdui, mdui.validate());
            }
        }
        if (spArray != null && spArray.length > 0) {
            List<UIInfoType> mduiExtensions = getMduiExtensions(spArray[0].getExtensions());
            for (UIInfoType mdui : mduiExtensions) {
                mduiList.add(new MduiExtVal(EntityType.sp, mdui));
                updateSchemaValid(ed.getEntityID(), SchemaType.mdui, mdui.validate());
            }
        }
        return mduiList;
    }

    /**
     * Get all MDUI extensions from an IDPSSODescriptor
     *
     * @param idpDesc An IDPSSODescriptor
     * @return A list of MDUI extensions
     */
    public static List<UIInfoType> getMduiExtensions(IDPSSODescriptorType idpDesc) {
        try {
            ExtensionsType extensions = idpDesc.getExtensions();
            return getMduiExtensions(extensions);
        } catch (Exception ex) {
            return new ArrayList<UIInfoType>();
        }
    }

    /**
     * Get all MDUI extensions from an IDPSSODescriptor
     *
     * @param spDesc An SPSSODescriptor
     * @return A list of MDUI extensions
     */
    public static List<UIInfoType> getMduiExtensions(SPSSODescriptorType spDesc) {
        try {
            ExtensionsType extensions = spDesc.getExtensions();
            return getMduiExtensions(extensions);
        } catch (Exception ex) {
            return new ArrayList<UIInfoType>();
        }
    }

    /**
     * Get all MDUI extensions from an Extension element
     *
     * @param extensions An Extension element
     * @return A list of MDUI extensions
     */
    public static List<UIInfoType> getMduiExtensions(ExtensionsType extensions) {
        List<UIInfoType> mduiList = new ArrayList<UIInfoType>();
        try {
            NodeList exNodes = extensions.getDomNode().getChildNodes();
            for (int i = 0; i < exNodes.getLength(); i++) {
                Node ext = exNodes.item(i);
                if (ext.getNodeName().endsWith(MDUI_ELEMENT) && ext.getNamespaceURI().equals(SAML_MDUI_NS)) {
                    UIInfoType extType = UIInfoDocument.Factory.parse(ext).getUIInfo();
                    mduiList.add(extType);
                }
            }
        } catch (Exception ex) {
        }
        return mduiList;
    }

    private void addDiscoLocations(EntityDescriptorType ed) {

        IdpDiscoVal discoVal = new IdpDiscoVal();
        List<String> locationList = discoVal.getLocationList();
        SPSSODescriptorType[] spArray = ed.getSPSSODescriptorArray();

        if (spArray != null && spArray.length > 0) {
            List<IndexedEndpointType> discoExtensions = getDiscoExtensions(spArray[0].getExtensions());
            for (IndexedEndpointType disco : discoExtensions) {
                String location = disco.getLocation();
                String binding = disco.getBinding();
                if (location != null && binding != null && location.length() > 4 && binding.equalsIgnoreCase(DISCO_BINDING)) {
                    locationList.add(location);
                }
                updateSchemaValid(ed.getEntityID(), SchemaType.disco, disco.validate());
            }
            if (!locationList.isEmpty()) {
                discoVal.setLocationList(locationList);
                discoLocationsMap.put(ed.getEntityID(), discoVal);
            }
        }
    }

    private static List<IndexedEndpointType> getDiscoExtensions(ExtensionsType extensions) {
        List<IndexedEndpointType> discoExtensions = new ArrayList<IndexedEndpointType>();
        try {
            NodeList exNodes = extensions.getDomNode().getChildNodes();
            for (int i = 0; i < exNodes.getLength(); i++) {
                Node ext = exNodes.item(i);
                if (ext.getNodeName().endsWith(DISCOVERY_RESPONSE_ELEMENT) && ext.getNamespaceURI().equals(DISCOVERY_RESPONSE_NS)) {
                    IndexedEndpointType extType = DiscoveryResponseDocument.Factory.parse(ext).getDiscoveryResponse();
                    discoExtensions.add(extType);
                }
            }
        } catch (Exception ex) {
        }
        return discoExtensions;
    }

    private void updateSchemaValid(String entityId, SchemaType type, boolean valid) {
        MdSchemaValid schemaValid;
        if (entitySchemaMap.containsKey(entityId)) {
            schemaValid = entitySchemaMap.get(entityId);
        } else {
            schemaValid = new MdSchemaValid();
        }

        switch (type) {
            case entityAttr:
                schemaValid.mdAttrPresent = true;
                if (!valid) {
                    schemaValid.mdAttrSchema = false;
                }
                break;
            case mdui:
                schemaValid.mduiPresent = true;
                if (!valid) {
                    schemaValid.mduiSchema = false;
                }
                break;
            case disco:
                schemaValid.discoPresent = true;
                if (!valid) {
                    schemaValid.discoSchema = false;
                }
                break;
            case entityDescr:
                if (!valid) {
                    schemaValid.mdSchema = false;
                }
                break;
            default:
                throw new AssertionError(type.name());
        }
        entitySchemaMap.put(entityId, schemaValid);
    }

    private void updateDocSchemaValid() {
        overallSchemaValid = new MdSchemaValid();
        Set<String> keySet = entitySchemaMap.keySet();
        for (String entityId : keySet) {
            MdSchemaValid sv = entitySchemaMap.get(entityId);
            // Recod precense of schema elements
            if (sv.discoPresent) {
                overallSchemaValid.discoPresent = true;
            }
            if (sv.mdAttrPresent) {
                overallSchemaValid.mdAttrPresent = true;
            }
            if (sv.mduiPresent) {
                overallSchemaValid.mduiPresent = true;
            }
            // Recod validity of svema elements
            overallSchemaValid.mdSchema = metadataDoc.getEntitiesDescriptor().validate();
            if (!sv.discoSchema) {
                overallSchemaValid.discoSchema = false;
            }
            if (!sv.mdAttrSchema) {
                overallSchemaValid.mdAttrSchema = false;
            }
            if (!sv.mduiSchema) {
                overallSchemaValid.mduiSchema = false;
            }
        }
    }

    /**
     * Collects all localized strings from an array of localized names
     *
     * @param names An array of localized strings
     * @return A Map of strings keyd by language code (2 letter language code)
     */
    public static Map<String, String> getLocalizedNames(LocalizedNameType[] names) {
        Map<String, String> nameMap = new HashMap<String, String>();
        for (LocalizedNameType name : names) {
            try {
                nameMap.put(name.getLang(), name.getStringValue());
            } catch (Exception ex) {
            }
        }
        return nameMap;
    }

    private void addUploadedEntityDescriptors(List<EntityDescriptorType> uploadedEntityDescriptors) {
        try {
            EntitiesDescriptorType entitiesDescriptor = metadataDoc.getEntitiesDescriptor();
            EntityDescriptorType[] entityDescriptorArray = entitiesDescriptor.getEntityDescriptorArray();
            List<EntityDescriptorType> edList = new ArrayList<EntityDescriptorType>();
            edList.addAll(Arrays.asList(entityDescriptorArray));
            for (EntityDescriptorType uplEd : uploadedEntityDescriptors) {
                String uplEntityID = uplEd.getEntityID();
                boolean swapped = false;
                if (uplEntityID != null) {
                    int cnt = 0, match = 0;
                    for (EntityDescriptorType ed : edList) {
                        String entityID = ed.getEntityID() != null ? ed.getEntityID() : "";
                        if (entityID.equals(uplEntityID)) {
                            match = cnt;
                            swapped = true;
                        }
                        cnt++;
                    }
                    if (swapped) {
                        edList.set(match, uplEd);
                    } else {
                        edList.add(uplEd);
                    }
                }
            }
            entitiesDescriptor.setEntityDescriptorArray(edList.toArray(new EntityDescriptorType[]{}));
            metadataDoc.setEntitiesDescriptor(entitiesDescriptor);
        } catch (Exception ex) {
        }
    }

    public EntitiesDescriptorDocument getMetadataDoc() {
        return metadataDoc;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public SigVerifyResult getSigVerifyResult() {
        return sigVerifyResult;
    }

    public boolean isSigPkMatch() {
        return sigPkMatch;
    }

    public boolean isSigIdAttributeVerified() {
        return sigIdAttributeVerified;
    }

    public X509Certificate getVerifyCert() {
        return verifyCert;
    }

    public List<EntityDescriptorType> getEntityList() {
        return entityList;
    }

    public Map<EntityType, List<EntityDescriptorType>> getEntityTypeMap() {
        return entityTypeMap;
    }

    public Document getMetadata() {
        return metadata;
    }

    public String[] getSigServiceEntityId() {
        return sigServiceEntityId;
    }

    public long getCreated() {
        return created;
    }

    /**
     * Returns all EntityAttributes in the metadata
     *
     * @return a Map keyed by entityID having a second Map as value. The second
     * Map is keyed by attribute name, providing a List of attribute values for
     * that named attribute type.
     */
    public Map<String, Map<String, List<EntityAttributeVal>>> getEntityAttributeMap() {
        return entityAttributeMap;
    }

    /**
     * Returns all MDUI extensions from metadata
     *
     * @return A Map keyed by entityID providing a list of MDUI extensions
     */
    public Map<String, List<MduiExtVal>> getEntityMduiMap() {
        return entityMduiMap;
    }

    public MdSchemaValid getOverallSchemaValid() {
        return overallSchemaValid;
    }

    public Map<String, MdSchemaValid> getEntitySchemaMap() {
        return entitySchemaMap;
    }

    public Map<String, IdpDiscoVal> getDiscoLocationsMap() {
        return discoLocationsMap;
    }

    public Map<String, EntityDescriptorType> getEntityMap() {
        return entityMap;
    }

    public enum SchemaType {

        entityDescr, entityAttr, mdui, disco;
    }
}
