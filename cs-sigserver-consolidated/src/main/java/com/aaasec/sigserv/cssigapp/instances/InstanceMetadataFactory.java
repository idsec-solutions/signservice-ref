/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.instances;

import com.aaasec.lib.crypto.xml.SignedXmlDoc;
import com.aaasec.lib.crypto.xml.XMLSign;
import com.aaasec.lib.crypto.xml.XmlBeansUtil;
import com.aaasec.lib.crypto.xml.XmlUtils;
import com.aaasec.lib.utils.FileOps;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import java.io.File;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.aaasec.sigserv.cssigapp.utils.NamedKeyStore;
import oasisNamesTcSAMLMetadataAttribute.EntityAttributesDocument;
import oasisNamesTcSAMLMetadataAttribute.EntityAttributesType;
import oasisNamesTcSAMLMetadataUi.LogoType;
import oasisNamesTcSAMLMetadataUi.UIInfoDocument;
import oasisNamesTcSAMLMetadataUi.UIInfoType;
import org.apache.xmlbeans.GDuration;
import org.apache.xmlbeans.XmlBase64Binary;
import org.apache.xmlbeans.XmlCursor;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.apache.xmlbeans.XmlString;
import org.w3.x2000.x09.xmldsig.KeyInfoType;
import org.w3.x2000.x09.xmldsig.X509DataType;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import x0Assertion.oasisNamesTcSAML2.AttributeType;
import x0Metadata.oasisNamesTcSAML2.ContactType;
import x0Metadata.oasisNamesTcSAML2.ContactTypeType;
import x0Metadata.oasisNamesTcSAML2.EntitiesDescriptorDocument;
import x0Metadata.oasisNamesTcSAML2.EntitiesDescriptorType;
import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;
import x0Metadata.oasisNamesTcSAML2.ExtensionsType;
import x0Metadata.oasisNamesTcSAML2.IndexedEndpointType;
import x0Metadata.oasisNamesTcSAML2.LocalizedNameType;
import x0Metadata.oasisNamesTcSAML2.LocalizedURIType;
import x0Metadata.oasisNamesTcSAML2.OrganizationType;
import x0Metadata.oasisNamesTcSAML2.SPSSODescriptorType;

/**
 *
 * @author stefan
 */
public class InstanceMetadataFactory {

    private static final Logger LOG = Logger.getLogger(InstanceMetadataFactory.class.getName());
    private final Instances instances;
    private final String dataDir;
    private EntitiesDescriptorDocument metadataDoc;
    private EntitiesDescriptorType entitiesDescriptor;
    private final long validityDurationMilliseconds;
    private final int cacheDurationMinutes;
    private InstanceConfig instConf;

    public InstanceMetadataFactory(InstanceConfig instConf) {
        this.instConf = instConf;
        this.instances = instConf.getInstances();
        this.validityDurationMilliseconds = (long) instances.getMetadataValidityMinutes() * 60000;
        this.cacheDurationMinutes = instances.getMetadataCacheDurationMinutes();
        this.dataDir = FileOps.getfileNameString(ContextParameters.getDataLocation(), "instances");
    }

    public void storeInstanceMetadata() throws Exception {
        instConf.reloadConf();
        metadataDoc = EntitiesDescriptorDocument.Factory.newInstance();
        entitiesDescriptor = metadataDoc.addNewEntitiesDescriptor();

        Map<String, Instance> instanceMap = instConf.getInstanceMap();
        Set<String> instanceNames = instanceMap.keySet();

        for (String instanceName : instanceNames) {
            try {
                setEntityDescriptor(instanceName, instanceMap.get(instanceName), entitiesDescriptor.addNewEntityDescriptor());
            } catch (XmlException ex) {
                Logger.getLogger(InstanceMetadataFactory.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        //Set attributes for valid until and cache duration
        Calendar validUntil = Calendar.getInstance();
        validUntil.setTimeInMillis(System.currentTimeMillis() + validityDurationMilliseconds);
        entitiesDescriptor.setValidUntil(validUntil);
        entitiesDescriptor.setCacheDuration(getDuration());

        //Sign metadata;
        byte[] metadataBytes = XmlBeansUtil.getStyledBytes(metadataDoc);

        if (metadataBytes == null) {
            LOG.warning("Error reading stage metadata file");
            return;
        }

        Document doc;
        try {
            doc = XmlUtils.getDocument(metadataBytes);
        } catch (Exception ex) {
            LOG.warning("Error parsing stage metadata file as XML doc");
            return;
        }
        NodeList esdNodeList = doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata", "EntitiesDescriptor");
        int nodeListLength = esdNodeList.getLength();

        if (nodeListLength < 1) {
            LOG.warning("No EntitiesDescriptor element in stage metadata file as XML doc");
            return;
        }
        Node sigParentNode = esdNodeList.item(0);
        NamedKeyStore mdSignKs = instConf.getInstancesKeyStore();
        SignedXmlDoc signedXML = XMLSign.getSignedXML(metadataBytes, mdSignKs.getPrivate(), mdSignKs.getKsCert(), sigParentNode, false, false);

        saveMetadata(signedXML.sigDocBytes);

    }

    private void saveMetadata(byte[] sigDocBytes) {
        File metadataFile = new File(ContextParameters.getCompleteCaFileSorageLocation(), "metadata.xml");
        FileOps.saveByteFile(sigDocBytes, metadataFile);
    }

    private GDuration getDuration() {
        GDuration duration = new GDuration(1, 0, 0, 0, 0, cacheDurationMinutes, 0, BigDecimal.ZERO);
        return duration;
    }

    private void setEntityDescriptor(String instName, Instance instance, EntityDescriptorType ed) throws XmlException {
        InstanceMetadata instanceMetadata = instance.getInstanceMetadata();
        ed.setEntityID(instance.getEntityId());
        ExtensionsType extensions = ed.addNewExtensions();

        EntityAttributesDocument eaDoc = EntityAttributesDocument.Factory.newInstance();
        EntityAttributesType ea = eaDoc.addNewEntityAttributes();
        List<String> entityCategoryList = instanceMetadata.getEntityCategoryList();
        if (entityCategoryList != null && !entityCategoryList.isEmpty()) {
            AttributeType ecAttr = ea.addNewAttribute();
            ecAttr.setName("http://macedir.org/entity-category");
            ecAttr.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
            for (String eCat : entityCategoryList) {
                XmlObject ecAttrVal = ecAttr.addNewAttributeValue();
                XmlString ecStrVal = XmlString.Factory.newInstance();
                ecStrVal.setStringValue(eCat);
                ecAttrVal.set(ecStrVal);
            }
        }

        addXmlObject(eaDoc, extensions);

        SPSSODescriptorType spssoDesc = ed.addNewSPSSODescriptor();
        spssoDesc.setProtocolSupportEnumeration(Arrays.asList(new String[]{"urn:oasis:names:tc:SAML:2.0:protocol"}));
        spssoDesc.setAuthnRequestsSigned(true);
        spssoDesc.setWantAssertionsSigned(true);
        ExtensionsType spssoExt = spssoDesc.addNewExtensions();
        UIInfoDocument mduiDoc = getMDUIdoc(instanceMetadata, instName);
        addXmlObject(mduiDoc, spssoExt);

        //set cert
        KeyInfoType keyInfo = spssoDesc.addNewKeyDescriptor().addNewKeyInfo();
        XmlString keyName = keyInfo.addNewKeyName();
        keyName.setStringValue(instance.getEntityId());
        X509DataType certData = keyInfo.addNewX509Data();
        X509Certificate ksCert = instConf.getInstanceKeyStoreMap().get(instName).getKsCert();
        XmlString subjectDn = certData.addNewX509SubjectName();
        subjectDn.setStringValue(ksCert.getSubjectX500Principal().toString());
        XmlBase64Binary certBinary = certData.addNewX509Certificate();
        try {
            certBinary.setByteArrayValue(ksCert.getEncoded());
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(InstanceMetadataFactory.class.getName()).log(Level.SEVERE, null, ex);
        }

        //Set AssertionConsumerService
        IndexedEndpointType assertConsumerService = spssoDesc.addNewAssertionConsumerService();
        assertConsumerService.setBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        assertConsumerService.setIndex(0);
        assertConsumerService.setLocation(ContextParameters.getSigRequestAndAssertionConsumerUrl());

        //Add org
        addOrgDetails(ed, instanceMetadata);
        addSupportContact(ed, instanceMetadata);
        assTechnicalContact(ed, instanceMetadata);

    }

    private void addXmlObject(XmlObject newObject, XmlObject containter) {
        XmlCursor containerCursor = containter.newCursor();
        containerCursor.toNextToken();
        XmlCursor newObjectsCursor = newObject.newCursor();
        newObjectsCursor.toFirstChild();
        newObjectsCursor.copyXml(containerCursor);
        containerCursor.dispose();
        newObjectsCursor.dispose();

    }

    private UIInfoDocument getMDUIdoc(InstanceMetadata instanceMd, String instanceName) {
        UIInfoDocument mduiDoc = UIInfoDocument.Factory.newInstance();
        UIInfoType mdui = mduiDoc.addNewUIInfo();

        LangStrings desc = instanceMd.getDescription();
        LangStrings dispName = instanceMd.getDisplayName();
        List<MetadataLogo> logoList = instanceMd.getLogoList();

        if (desc != null) {
            for (String lang : desc.getLangList()) {
                LocalizedNameType descElm = mdui.addNewDescription();
                descElm.setLang(lang);
                descElm.setStringValue(desc.getVal(lang));
            }
        }
        if (dispName != null) {
            for (String lang : dispName.getLangList()) {
                LocalizedNameType descElm = mdui.addNewDisplayName();
                descElm.setLang(lang);
                descElm.setStringValue(dispName.getVal(lang));
            }
        }
        if (logoList == null) {
            return mduiDoc;
        }

        for (MetadataLogo logo : logoList) {
            LogoType logoElm = mdui.addNewLogo();
            logoElm.setHeight(new BigInteger(logo.getHeight()));
            logoElm.setWidth(new BigInteger(logo.getWidth()));
            //ContextParameters.getConf().getCaDistributionUrl();
            logoElm.setStringValue(getLogoUrl(instanceName, logo.getLogoFileName()));
        }

        return mduiDoc;
    }

    private void addOrgDetails(EntityDescriptorType ed, InstanceMetadata instanceMetadata) {
        LangStrings orgDisplayName = instanceMetadata.getOrgDisplayName();
        LangStrings orgName = instanceMetadata.getOrgName();
        LangStrings orgURL = instanceMetadata.getOrgURL();

        if (orgDisplayName == null && orgName == null && orgURL == null) {
            return;
        }

        OrganizationType org = ed.addNewOrganization();

        if (orgDisplayName != null) {
            for (String lang : orgDisplayName.getLangList()) {
                LocalizedNameType organizationDisplayName = org.addNewOrganizationDisplayName();
                organizationDisplayName.setLang(lang);
                organizationDisplayName.setStringValue(orgDisplayName.getVal(lang));
            }
        }
        if (orgName != null) {
            for (String lang : orgName.getLangList()) {
                LocalizedNameType organizationName = org.addNewOrganizationName();
                organizationName.setLang(lang);
                organizationName.setStringValue(orgName.getVal(lang));
            }
        }
        if (orgURL != null) {
            for (String lang : orgURL.getLangList()) {
                LocalizedURIType organizationURL = org.addNewOrganizationURL();
                organizationURL.setLang(lang);
                organizationURL.setStringValue(orgURL.getVal(lang));
            }
        }
    }

    private void addSupportContact(EntityDescriptorType ed, InstanceMetadata instanceMetadata) {
        String supContactGivenName = instanceMetadata.getSupContactGivenName();
        String supContactSurName = instanceMetadata.getSupContactSurName();
        String supContactEmail = instanceMetadata.getSupContactEmail();
        String supContactTel = instanceMetadata.getSupContactTel();

        if (supContactGivenName == null && supContactSurName == null && supContactEmail == null && supContactTel == null) {
            return;
        }

        ContactType contactPerson = ed.addNewContactPerson();
        contactPerson.setContactType(ContactTypeType.SUPPORT);
        setContactDetails(contactPerson, supContactGivenName, supContactSurName, supContactEmail, supContactTel);

    }

    private void assTechnicalContact(EntityDescriptorType ed, InstanceMetadata instanceMetadata) {
        String techContactGivenName = instanceMetadata.getTechContactGivenName();
        String techContactSurName = instanceMetadata.getTechContactSurName();
        String techContactEmail = instanceMetadata.getTechContactEmail();
        String techContactTel = instanceMetadata.getTechContactTel();

        if (techContactGivenName == null && techContactSurName == null && techContactEmail == null && techContactTel == null) {
            return;
        }

        ContactType contactPerson = ed.addNewContactPerson();
        contactPerson.setContactType(ContactTypeType.TECHNICAL);
        setContactDetails(contactPerson, techContactGivenName, techContactSurName, techContactEmail, techContactTel);
    }

    private void setContactDetails(ContactType contact, String givenName, String surname, String email, String tel) {
        if (givenName != null) {
            contact.setGivenName(givenName);
        }
        if (surname != null) {
            contact.setSurName(surname);
        }
        if (email != null) {
            contact.addEmailAddress(email);
        }
        if (tel != null) {
            contact.addTelephoneNumber(tel);
        }
    }

    private String getLogoUrl(String instanceName, String logoFileName) {
        String caDistributionUrl = ContextParameters.getPublicationUrl();
        String logoUrl = FileOps.getfileNameString(caDistributionUrl, "logos/" + instanceName + "/" + logoFileName);
        File orgLogoFile = new File(ContextParameters.getDataLocation(), "instances/" + instanceName + "/" + logoFileName);
        File destLogoFile = new File(ContextParameters.getCompleteCaFileSorageLocation(), "logos/" + instanceName + "/" + logoFileName);
        if (orgLogoFile.canRead()) {
            destLogoFile.getParentFile().mkdirs();
            FileOps.saveByteFile(FileOps.readBinaryFile(orgLogoFile), destLogoFile);
        }
        return logoUrl;
    }

}
