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
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import oasisNamesTcSAMLMetadataUi.UIInfoDocument;
import oasisNamesTcSAMLMetadataUi.UIInfoType;
import org.apache.xmlbeans.XmlException;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import x0Metadata.oasisNamesTcSAML2.EntitiesDescriptorDocument;
import x0Metadata.oasisNamesTcSAML2.ExtensionsType;

/**
 * Class for parsing SAML Metadata.
 */
public final class LoclFileMetaDataSource extends MetaData {

    private Document doc;
    private File xmlFile;
    private Thread recacheThread;
    private long cacheInterval;
    private final static Logger LOG = Logger.getLogger(LoclFileMetaDataSource.class.getName());
    private static long lastRecache;

    public LoclFileMetaDataSource(File xmlFile, int refreshMinutes) {
        this.xmlFile = xmlFile;
        this.refreshMinutes = refreshMinutes;
        if (xmlFile.canRead()) {
            LOG.fine("Can read metadata cache - " + xmlFile.getAbsolutePath());
        } else {
            LOG.warning("no metadata cache - " + xmlFile.getAbsolutePath());
        }
        cacheInterval = refreshMinutes * 1000 * 60;
        lastRecache = System.currentTimeMillis();
        start();
    }

    public void start() {
        try {
            InputStream is = new FileInputStream(xmlFile);

            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            doc = dBuilder.parse(is);
            doc.getDocumentElement().normalize();
            entityDescriptorMap = extractEntityDescriptorMap(doc);
            parseMetadata();
            lastRecache = System.currentTimeMillis();

        } catch (Exception ex) {
            LOG.log(Level.WARNING, null, ex);
        }
    }

    protected void parseMetadata() {
        try {
            entityIds = new ArrayList<String>();
            nameMap = new HashMap<String, Map>();
            certMap = new HashMap<String, List<String>>();
            typeMap = new HashMap<String, EntityType>();
            HashMap<String, String> idpDisplName;

            NodeList entityNodes = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "EntityDescriptor");
            for (int i = 0; i < entityNodes.getLength(); i++) {
                Node entityNode = entityNodes.item(i);
                NodeList entityElements = entityNode.getChildNodes();

                if (entityElements.item(1).getNodeName().indexOf("IDPSSODescriptor") != -1) {
                    String entityID = entityNode.getAttributes().getNamedItem("entityID").getTextContent();
                    entityIds.add(entityID);
                    idpDisplName = new HashMap<String, String>();
                    nameMap.put(entityID, idpDisplName);
                }
            }

            String[] types = {"IDPSSODescriptor", "SPSSODescriptor"};
            for (String type : types) {
                NodeList typeNodes = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", type);
                for (int i = 0; i < typeNodes.getLength(); i++) {
                    Node orgNode = typeNodes.item(i);
                    String parentEntityId = getParentEntityId(orgNode);
                    if (parentEntityId == null) {
                        continue;
                    }
                    EntityType entityType = EntityType.getEntityType(type, "urn:oasis:names:tc:SAML:2.0:metadata");
                    addEntityId(parentEntityId);
                    if (!typeMap.containsKey(parentEntityId)) {
                        typeMap.put(parentEntityId, entityType);
                    }
                }
            }

            types = new String[]{"X509Certificate", "ds:X509Certificate"};
            for (String type : types) {

                NodeList certNodes = doc.getElementsByTagName(type);
                for (int i = 0; i < certNodes.getLength(); i++) {
                    Node certNode = certNodes.item(i);
                    String parentEntityId = getParentEntityId(certNode);
                    if (parentEntityId == null) {
                        continue;
                    }
                    boolean signCert = isSignCert(certNode);
                    if (!signCert) {
                        continue;
                    }
                    String cert = certNode.getTextContent();
                    List<String> certList = certMap.containsKey(parentEntityId) ? certMap.get(parentEntityId) : new ArrayList<String>();
                    if (cert != null && cert.length() > 0) {
                        certList.add(cert);
                        certMap.put(parentEntityId, certList);
                    }
                }
            }

            types = new String[]{"OrganizationDisplayName", "md:OrganizationDisplayName"};
            for (String type : types) {
                NodeList orgNodes = doc.getElementsByTagName(type);
                for (int i = 0; i < orgNodes.getLength(); i++) {
                    Node orgNode = orgNodes.item(i);
                    String parentEntityId = getParentEntityId(orgNode);
                    if (parentEntityId == null) {
                        continue;
                    }
                    addEntityId(parentEntityId);
                    addToNameMap(orgNode, parentEntityId);

                }
            }
            LOG.fine("Metadata Initialized: Names (" + nameMap.size() + ") Certs(" + certMap.size() + ") types(" + typeMap.size() + ")");
            initialized = true;
        } catch (NullPointerException ex) {
            initialized = false;
        }
    }

    static UIInfoType getUIInfoList(ExtensionsType ext) {
        if (ext == null) {
            return null;
        }
        Node domNode = ext.getDomNode();
        NodeList childNodes = domNode.getChildNodes();
        int length = childNodes.getLength();
        for (int i = 0; i < length; i++) {
            Node node = childNodes.item(i);
            String nodeName = node.getLocalName();
            if (nodeName != null) {
                if (nodeName.equals("UIInfo")) {
                    try {
                        UIInfoDocument mduiDoc = UIInfoDocument.Factory.parse(node);
                        return mduiDoc.getUIInfo();
                    } catch (XmlException ex) {
                    }
                }
            }
        }
        return null;
    }

    private String getParentEntityId(Node node) {
        Node p = node.getParentNode();

        try {
            while (p != null && p.getNodeName().indexOf("EntityDescriptor") == -1) {
                p = p.getParentNode();
            }
            if (p != null) {
                String entityID = p.getAttributes().getNamedItem("entityID").getTextContent();
                return entityID;
            }
        } catch (Exception ex) {
        }
        return null;
    }

    private boolean isSignCert(Node certNode) {
        boolean signCert = false;
        Node p = certNode.getParentNode();

        try {
            while (p != null && p.getNodeName().indexOf("KeyDescriptor") == -1) {
                p = p.getParentNode();
            }
            if (p != null) {
                Node useAttr = p.getAttributes().getNamedItem("use");
                signCert = true;
                // If a use attribute is present and it states someting other than signing, reject
                if (useAttr != null) {
                    String useAttrValue = useAttr.getTextContent();
                    if (!useAttrValue.equalsIgnoreCase("signing")) {
                        signCert = false;
                    }
                }
            }
        } catch (Exception ex) {
        }
        return signCert;
    }

    private void addToNameMap(Node orgNode, String entityID) {
        String lang = orgNode.getAttributes().getNamedItem("xml:lang").getTextContent();
        String orgDisp = orgNode.getTextContent();
        //Store Idp Name
        Map<String, String> idpDisplName = nameMap.get(entityID);
        idpDisplName.put(lang, orgDisp);
    }

    private void addEntityId(String entityId) {
        if (!entityIds.contains(entityId)) {
            entityIds.add(entityId);
            Map<String, String> idpDisplName = new HashMap<String, String>();
            nameMap.put(entityId, idpDisplName);
        }
    }

}
