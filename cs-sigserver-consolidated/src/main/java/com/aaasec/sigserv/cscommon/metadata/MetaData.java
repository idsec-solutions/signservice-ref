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
import org.w3c.dom.Document;
import x0Metadata.oasisNamesTcSAML2.EntitiesDescriptorDocument;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorDocument;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;

import java.util.*;

/**
 * Class for parsing SAML Metadata.
 */
public abstract class MetaData {

    protected List<String> entityIds = new ArrayList<String>();
    protected Map<String, List<String>> idpSupportedClassRefMap = new HashMap<String, List<String>>();
    protected Map<String, Map> nameMap = new HashMap<String, Map>();
    protected Map<String, List<String>> certMap = new HashMap<String, List<String>>();
    protected Map<String, String> encCertMap = new HashMap<String, String>();
    protected Map<String, EntityType> typeMap = new HashMap<String, EntityType>();
    protected Map<String, Map<String, String>> ssoMap = new HashMap<String, Map<String, String>>();
    protected boolean initialized = false;
    protected static final String LF = System.getProperty("line.separator");
    protected int refreshMinutes = 60;
    protected Map<String, EntityDescriptorType> entityDescriptorMap;
    
    protected abstract void parseMetadata();
//    protected abstract void reCache();

    protected Map<String, EntityDescriptorType> extractEntityDescriptorMap(Document doc){
        Map<String, EntityDescriptorType> edMap = new HashMap<>();

        try {
            EntitiesDescriptorDocument edsDoc = EntitiesDescriptorDocument.Factory.parse(doc);
            Arrays.stream(edsDoc.getEntitiesDescriptor().getEntityDescriptorArray())
                    .forEach(ed -> edMap.put(ed.getEntityID(), ed));
            return edMap;
        } catch (Exception ex){
        }

        try {
            EntityDescriptorType ed = EntityDescriptorDocument.Factory.parse(doc).getEntityDescriptor();
            edMap.put(ed.getEntityID(),ed);
        } catch (Exception ex){
        }
        return edMap;
    }

    public List<String> getEntityIds() {
        return entityIds;
    }

    public boolean isInitialized() {
        return initialized;
    }

    public Map<String, List<String>> getCertMap() {
        return certMap;
    }

    public Map<String, Map> getNameMap() {
        return nameMap;
    }

    public Map<String, String> getEncCertMap() {
        return encCertMap;
    }

    public String getName(String entityId, String prefLang) {
        String name = entityId;
        try {
            Map langMap = nameMap.get(entityId);
            if (langMap.containsKey(prefLang)) {
                return (String) langMap.get(prefLang);
            }
            if (langMap.containsKey("en")) {
                return (String) langMap.get("en");
            }
        } catch (Exception ex) {
        }
        return name;
    }

    public Map<String, EntityType> getTypeMap() {
        return typeMap;
    }  

    public Map<String, Map<String, String>> getSSOMap() {
        return ssoMap;
    }

    public Map<String, List<String>> getIdpSupportedClassRefMap() {
        return idpSupportedClassRefMap;
    }

    public Map<String, EntityDescriptorType> getEntityDescriptorMap() {
        return entityDescriptorMap;
    }
}
