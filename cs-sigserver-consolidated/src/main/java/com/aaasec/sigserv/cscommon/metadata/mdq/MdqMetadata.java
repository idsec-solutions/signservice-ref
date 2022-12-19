package com.aaasec.sigserv.cscommon.metadata.mdq;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

import org.apache.commons.lang.StringUtils;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;
import org.apache.xmlbeans.impl.values.XmlAnyTypeImpl;
import org.bouncycastle.util.encoders.Base64;
import org.w3.x2000.x09.xmldsig.X509DataType;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.metadata.EntityAttributeVal;
import com.aaasec.sigserv.cscommon.metadata.EntityType;
import com.aaasec.sigserv.cscommon.metadata.MduiExtVal;
import com.aaasec.sigserv.cscommon.metadata.MetaData;
import com.aaasec.sigserv.cscommon.metadata.MetadataConstants;

import oasisNamesTcSAMLMetadataAttribute.EntityAttributesDocument;
import oasisNamesTcSAMLMetadataAttribute.EntityAttributesType;
import oasisNamesTcSAMLMetadataUi.UIInfoDocument;
import oasisNamesTcSAMLMetadataUi.UIInfoType;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0Metadata.oasisNamesTcSAML2.EndpointType;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;
import x0Metadata.oasisNamesTcSAML2.ExtensionsType;
import x0Metadata.oasisNamesTcSAML2.IDPSSODescriptorType;
import x0Metadata.oasisNamesTcSAML2.KeyDescriptorType;
import x0Metadata.oasisNamesTcSAML2.KeyTypes;
import x0Metadata.oasisNamesTcSAML2.LocalizedNameType;
import x0Metadata.oasisNamesTcSAML2.SPSSODescriptorType;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class MdqMetadata implements MetaData, MetadataConstants {

  private static final Logger LOG = Logger.getLogger(MdqMetadata.class.getName());

  private final String baseUrl;
  private final X509Certificate mdCert;
  private boolean initialized;

  private Map<String, MetadataEntityData> entityDataMap;

  public MdqMetadata(String baseUrl, X509Certificate mdCert) {
    this.baseUrl = baseUrl;
    this.mdCert = mdCert;
    this.entityDataMap = new HashMap<>();
    initialized = true;
  }

  @Override public boolean isEntityIdSupported(String entityId) {
    return updateEntityDataMap(entityId);
  }

  @Override public boolean isInitialized() {
    return initialized;
  }

  @Override public List<String> getCertificates(String entityId) {
    return updateEntityDataMap(entityId)
      ? entityDataMap.get(entityId).getCertificateList()
      : null;
  }

  @Override public Map<String, String> getNameMap(String entityId) {
    return updateEntityDataMap(entityId)
      ? entityDataMap.get(entityId).getNameMap()
      : null;
  }

  @Override public String getEncCert(String entityId) {
    return updateEntityDataMap(entityId)
      ? entityDataMap.get(entityId).getEncCertificate()
      : null;
  }

  @Override public String getName(String entityId, String prefLang) {
    if (!updateEntityDataMap(entityId)) {
      return null;
    }

    String name = entityId;
    try {
      Map langMap = entityDataMap.get(entityId).getNameMap();
      if (langMap.containsKey(prefLang)) {
        return (String) langMap.get(prefLang);
      }
      if (langMap.containsKey("en")) {
        return (String) langMap.get("en");
      }
    }
    catch (Exception ex) {
    }
    return name;

  }

  public Map<String, MetadataEntityData> getEntityDataMap() {
    return entityDataMap;
  }

  @Override public EntityType getEntityType(String entityId) {
    return updateEntityDataMap(entityId)
      ? entityDataMap.get(entityId).getEntityType()
      : null;
  }

  @Override public Map<String, String> getSSOMap(String entityId) {
    return updateEntityDataMap(entityId)
      ? entityDataMap.get(entityId).getSsoMap()
      : null;
  }

  @Override public List<String> getIdpSupportedClassRefs(String entityId) {
    return updateEntityDataMap(entityId)
      ? entityDataMap.get(entityId).getIdpSupportedLoAList()
      : null;
  }

  @Override public EntityDescriptorType getEntityDescriptor(String entityId) {
    return updateEntityDataMap(entityId)
      ? entityDataMap.get(entityId).getEntityDescriptor()
      : null;
  }

  /**
   * Main function to update the entity data map with available MD record via MDX
   *
   * @param entityId entity ID to update
   * @return true if the requested entity ID is present in the metadata source and was successfully downloaded
   */
  private boolean updateEntityDataMap(String entityId) {

    LOG.fine("Checking MDQ metadata presence for " + entityId);

    if (entityDataMap.containsKey(entityId)) {
      // We already have this entityID. Check if it is still valid
      MetadataEntityData currentEntityData = entityDataMap.get(entityId);
      if (currentEntityData.getExpires().isAfter(Instant.now())) {
        // Still valid. Stop here and return positive confirmation.
        LOG.fine("Returning valid metadata record from cache");
        return true;
      }
      LOG.fine("Existing metadata record has expired. Attempt to reload");
    }
    // We have no current valid instance of this entity ID. Attempt to get it.
    EntityDescriptorMdDoc metaDataDoc = new EntityDescriptorMdDoc(baseUrl, mdCert, entityId);
    if (!metaDataDoc.isValid()) {
      LOG.fine("Failed to load valid metadata from requested entityID " + entityId);
      return false;
    }

    //Check that this is an IdP
    EntityDescriptorType entityDescriptor = metaDataDoc.getMetadataDoc().getEntityDescriptor();
    IDPSSODescriptorType[] idpssoDescriptorArray = entityDescriptor.getIDPSSODescriptorArray();
    if (idpssoDescriptorArray == null || idpssoDescriptorArray.length == 0) {
      // no IdP. Return false
      return false;
    }

    // Whe have a valid IdP entry. Store data.
    MetadataEntityData mdEntityData = new MetadataEntityData();
    mdEntityData.setEntityId(entityId);
    mdEntityData.setEntityDescriptor(entityDescriptor);
    parseMetadata(entityDescriptor, mdEntityData);

    // Set valid until to one day from now, or to validUntil if it is shorter than one day from now.
    Calendar validUntil = entityDescriptor.getValidUntil();
    Instant oneDayFromNow = Instant.ofEpochMilli(System.currentTimeMillis() + Duration.ofDays(1).toMillis());
    if (validUntil == null) {
      mdEntityData.setExpires(oneDayFromNow);
    } else {
      Instant validUntilInstant = Instant.ofEpochMilli(validUntil.getTimeInMillis());
      if (validUntilInstant.isBefore(oneDayFromNow)){
        mdEntityData.setExpires(validUntilInstant);
      } else {
        mdEntityData.setExpires(oneDayFromNow);
      }
    }
    mdEntityData.setLastDownload(Instant.now());
    entityDataMap.put(entityId, mdEntityData);

    LOG.fine("Returning downloaded and re-cached metadata record");

    return true;
  }

  protected void parseMetadata(EntityDescriptorType ed, MetadataEntityData mdEntityData) {
    try {
/*
      Map<String, String> nameMap = new HashMap<>();
      List<String> certList = new ArrayList<>();
      EntityType entityType;
      List<String> idpSupportedClassRefList = new ArrayList<>();
*/

      List<MduiExtVal> mduiList = getAllMduiExtVals(ed);

      String entityId = ed.getEntityID();
      HashMap<String, String> idpDisplName = new HashMap<String, String>();

      //Get display name, primary from MDUI
      boolean hasMdui = false;
      if (!mduiList.isEmpty()) {
        for (MduiExtVal mdui : mduiList) {
          switch (mdui.entityType) {
          case idp:
          case sp:
            hasMdui = true;
            mdEntityData.setEntityType(mdui.entityType);
            UIInfoType uiInfo = mdui.mduiExt;
            LocalizedNameType[] displayNameArray = uiInfo.getDisplayNameArray();
            for (LocalizedNameType dispName : displayNameArray) {
              idpDisplName.put(dispName.getLang(), dispName.getStringValue());
            }
          }
        }
        mdEntityData.setNameMap(idpDisplName);
      }
      if (!hasMdui) {
        // in case this entity does not have any MDUI
        try {
          LocalizedNameType[] organizationDisplayNameArray = ed.getOrganization().getOrganizationDisplayNameArray();
          for (LocalizedNameType dispName : organizationDisplayNameArray) {
            idpDisplName.put(dispName.getLang(), dispName.getStringValue());
          }
          mdEntityData.setNameMap(idpDisplName);
        }
        catch (Exception ex) {
        }
      }
      //Get Cert
      try {
        IDPSSODescriptorType[] idpssoDescriptorArray = ed.getIDPSSODescriptorArray();
        if (idpssoDescriptorArray != null && idpssoDescriptorArray.length > 0) {
          addCerts(idpssoDescriptorArray[0].getKeyDescriptorArray(), mdEntityData);
        }
        SPSSODescriptorType[] spssoDescriptorArray = ed.getSPSSODescriptorArray();
        if (spssoDescriptorArray != null && spssoDescriptorArray.length > 0) {
          addCerts(spssoDescriptorArray[0].getKeyDescriptorArray(), mdEntityData);
        }
      }
      catch (Exception ex) {
      }

      try {
        IDPSSODescriptorType idpssoDescriptor = ed.getIDPSSODescriptorArray(0);
        EndpointType[] singleSignOnServiceArray = idpssoDescriptor.getSingleSignOnServiceArray();
        Map<String, String> idpSsoMap = new HashMap<String, String>();
        for (EndpointType ssos : singleSignOnServiceArray) {
          String binding = ssos.getBinding();
          String location = ssos.getLocation();
          idpSsoMap.put(binding, location);
        }
        mdEntityData.setSsoMap(idpSsoMap);
      } catch (Exception ex) {
      }

      // Get IdP supported context class refs
      try {
        Map<String, List<EntityAttributeVal>> entAttrMap = getEntityAttributes(ed);
        if (entAttrMap.containsKey("urn:oasis:names:tc:SAML:attribute:assurance-certification")) {
          List<String> classRefList = new ArrayList<String>();
          List<EntityAttributeVal> attrValList = entAttrMap.get(
            "urn:oasis:names:tc:SAML:attribute:assurance-certification");
          for (EntityAttributeVal attrVal : attrValList) {
            classRefList.add(attrVal.value.trim().toLowerCase());
          }
          mdEntityData.setIdpSupportedLoAList(classRefList);
        }
      }
      catch (Exception ex) {
      }
    }
    catch (Exception ex) {
    }
  }

  private void addCerts(KeyDescriptorType[] keyDescriptorArray, MetadataEntityData entityData) {
    int certCount = 0;
    List<String> certList = new ArrayList<String>();
    String encCert = null;
    for (KeyDescriptorType kd : keyDescriptorArray) {
      KeyTypes.Enum use = kd.getUse();
      if (use == null || use.equals(KeyTypes.SIGNING)) {
        byte[] certBytes = getKeyDescriptorCertBytes(kd);
        certList.add(Base64Coder.encodeLines(certBytes));
        certCount++;
      }
      entityData.setCertificateList(certList);

      if (use == null || use.equals(KeyTypes.ENCRYPTION)) {
        byte[] certBytes = getKeyDescriptorCertBytes(kd);
        encCert = Base64Coder.encodeLines(certBytes);
        certCount++;
      }
    }
    LOG.fine("Added " + certCount + " certificates");
    entityData.setCertificateList(certList);
    entityData.setEncCertificate(encCert);
  }

  private byte[] getKeyDescriptorCertBytes(KeyDescriptorType kd) {
    try {
      return kd.getKeyInfo().getX509DataArray(0).getX509CertificateArray(0);
    }
    catch (Exception ex) {
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
      for (int i = 0; i < childNodes.getLength(); i++) {
        Node childNode = childNodes.item(i);
        if (childNode.getNodeType() == Node.TEXT_NODE) {
          b.append(childNode.getNodeValue());
        }
      }
      String nodeValue = b.toString().trim();
      if (StringUtils.isNotBlank(nodeValue)) {
        byte[] certBytes = Base64.decode(nodeValue);
        if (certBytes != null && certBytes.length > 0) {
          return certBytes;
        }
      }
      if (StringUtils.isNotBlank(recoveredRawB64)) {
        byte[] certBytes = Base64.decode(recoveredRawB64);
        if (certBytes != null && certBytes.length > 0) {
          LOG.fine("Successfully recovered certificate bytes from XML parsing");
          return certBytes;
        }
      }
    }
    catch (Exception ex) {
      LOG.fine("Failed to recover certificate bytes form digital identity: " + ex);
      return null;
    }
    LOG.fine("Failed to recover certificate bytes from key descriptor: \n" + elementRawText);
    return null;
  }

  private String parseRawElement(String elementRawText) {
    int certElementStartIdx = elementRawText.indexOf("X509Certificate");
    if (certElementStartIdx == -1) {
      return null;
    }
    String certElementData = elementRawText.substring(certElementStartIdx);

    int dataStartIdx = certElementData.indexOf(">");
    if (dataStartIdx == -1) {
      return null;
    }
    String removeLeadingTag = certElementData.substring(dataStartIdx + 1);
    final int endIdx = removeLeadingTag.indexOf("<");
    return removeLeadingTag.substring(0, endIdx).trim();
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
      }
    }
    if (spArray != null && spArray.length > 0) {
      List<UIInfoType> mduiExtensions = getMduiExtensions(spArray[0].getExtensions());
      for (UIInfoType mdui : mduiExtensions) {
        mduiList.add(new MduiExtVal(EntityType.sp, mdui));
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
    }
    catch (Exception ex) {
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
    }
    catch (Exception ex) {
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
    }
    catch (Exception ex) {
    }
    return mduiList;
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
    }
    catch (Exception ex) {
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
                    List<EntityAttributeVal> valList = entAttributeMap.containsKey(attrName) ?
                      entAttributeMap.get(attrName) :
                      new ArrayList<EntityAttributeVal>();
                    valList.add(new EntityAttributeVal(nameFormat, attrName, value));
                    entAttributeMap.put(attrName, valList);
                  }
                }
                if (attrVal instanceof XmlAnyTypeImpl) {
                  String value = ((XmlAnyTypeImpl) attrVal).getStringValue();
                  if (value != null) {
                    List<EntityAttributeVal> valList = entAttributeMap.containsKey(attrName) ?
                      entAttributeMap.get(attrName) :
                      new ArrayList<EntityAttributeVal>();
                    valList.add(new EntityAttributeVal(nameFormat, attrName, value));
                    entAttributeMap.put(attrName, valList);
                  }
                }
              }
            }
          }
        }
      }
      catch (Exception ex) {
      }
    }
    return entAttributeMap;
  }

}
