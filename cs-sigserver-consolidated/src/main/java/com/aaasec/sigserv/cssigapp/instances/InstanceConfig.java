/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.instances;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import com.aaasec.sigserv.cssigapp.utils.NamedKeyStore;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.IOUtils;

/**
 *
 * @author stefan
 */
public final class InstanceConfig {

    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private File instancesFile;
    private Instances instances;
    private Map<String, Instance> instanceMap;
    private Map<String, NamedKeyStore> instanceKeyStoreMap;
    private Map<String, List<PublicKey>> trustedPublicKeyMap;
    private List<String> trustedSigners;
    private SecureRandom rnd = new SecureRandom();
    private String instancesDir;
    private NamedKeyStore instancesKeyStore;

    public InstanceConfig() {
        instancesDir = FileOps.getfileNameString(ContextParameters.getDataLocation(), "instances");
    }

    public Instances getInstances() {
        return instances;
    }

    public Map<String, Instance> getInstanceMap() {
        return instanceMap;
    }

    public Map<String, NamedKeyStore> getInstanceKeyStoreMap() {
        return instanceKeyStoreMap;
    }

    public Map<String, List<PublicKey>> getTrustedPublicKeyMap() {
        return trustedPublicKeyMap;
    }

    public NamedKeyStore getInstancesKeyStore() {
        return instancesKeyStore;
    }

    public List<String> getTrustedSigners() {
        return trustedSigners;
    }
    

    public void reloadConf() {
        instancesFile = new File(instancesDir, "instances.json");
        if (!instancesFile.canRead()) {
            makeMockupInstances();
        } else {
            getInstancesData();
        }
        List<String> instanceNames = instances.getInstanceNames();
        for (String name : instanceNames) {
            File instanceDir = getInstanceDir(name);
            File instanceFile = getInstanceFile(name);

            if (!instanceDir.exists() || !instanceFile.canRead()) {
                makeMockupInstance(name);
            }
        }
        getInstanceData();

    }

    private void makeMockupInstances() {
        instances = new Instances();

        instances.setMetaDataSignerKeyStore("MdSigner.jks");
        instances.setMetaDataSignerPass(new BigInteger(64, rnd).toString(16));
        instancesKeyStore = new NamedKeyStore(instances.getMetaDataSignerKeyStore(), "Signature Service Metadata Signer", "mdsigner", instances.getMetaDataSignerPass().toCharArray(), instancesDir);
        instances.setMetadataCacheDurationMinutes(60);
        instances.setMetadataValidityMinutes(60 * 24 * 7);
        instances.setInstanceNames(Arrays.asList(new String[]{"instance1", "instance2"}));

        instancesFile.getParentFile().mkdirs();
        FileOps.saveByteFile(gson.toJson(instances).getBytes(Charset.forName("UTF-8")), instancesFile);

    }

    private File getInstanceDir(String name) {
        return new File(instancesDir, name);
    }

    private File getInstanceFile(String name) {
        return new File(getInstanceDir(name), "instance.json");
    }

    private void makeMockupInstance(String name) {
        Instance inst = new Instance();

        inst.setEntityId("http://example.com/instance/" + name);
        inst.setKeyStoreName("instance.jks");
        inst.setKeyStorePass(new BigInteger(64, rnd).toString(16));
        NamedKeyStore instanceKs = new NamedKeyStore(inst.getKeyStoreName(), "Signing Service instance " + name, "instance", inst.getKeyStorePass().toCharArray(), getInstanceDir(name).getAbsolutePath());
        inst.setTrustStoreName("trustStore.jks");
        inst.setTrustStorePass("tsPass");
        makeEmptyTrustStore(name, inst.getTrustStoreName(), inst.getTrustStorePass());
        InstanceMetadata imd = new InstanceMetadata();
        imd.setDescription(new LangStrings(new String[]{"sv","en"},"Test Instance " + name));
        imd.setDisplayName(new LangStrings(new String[]{"sv","en"},"Test Instance " + name));
        imd.setEntityCategoryList(Arrays.asList(new String[]{"http://id.elegnamnden.se/st/1.0/sigservice", "http://id.elegnamnden.se/ec/1.0/loa3-pnr"}));
        InputStream logoIs = InstanceConfig.class.getClassLoader().getResourceAsStream("mocklogo.png");
        try {
            byte[] logoBytes = IOUtils.toByteArray(logoIs);
            File logoFile = new File(getInstanceDir(name), "logo.png");
            FileOps.saveByteFile(logoBytes, logoFile);
            imd.setLogoList(Arrays.asList(new MetadataLogo[]{new MetadataLogo("85", "150", "logo.png")}));
        } catch (IOException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        imd.setOrgDisplayName(new LangStrings(new String[]{"sv","en"},"Org Disp Name " + name));
        imd.setOrgName(new LangStrings(new String[]{"sv","en"},"Org Name " + name));
        imd.setOrgURL(new LangStrings(new String[]{"sv","en"},"http://example.com"));
        imd.setSupContactEmail("contact@example.com");
        imd.setTechContactEmail("contact@example.com");
        imd.setSupContactGivenName("GivenName");
        imd.setTechContactGivenName("GivenName");
        imd.setSupContactSurName("Surname");
        imd.setTechContactSurName("Surname");
        imd.setSupContactTel("010-111111");
        imd.setTechContactTel("010-111111");

        inst.setInstanceMetadata(imd);

        String instanceJson = gson.toJson(inst);
        File instanceFile = getInstanceFile(name);
        instanceFile.getParentFile().mkdirs();
        FileOps.saveByteFile(instanceJson.getBytes(Charset.forName("UTF-8")), instanceFile);
    }

    private void makeEmptyTrustStore(String name, String trustStoreName, String keyStorePass) {
        try {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, null);
            File ksFile = new File(getInstanceDir(name), trustStoreName);
            FileOutputStream fos = new FileOutputStream(ksFile);
            trustStore.store(fos, keyStorePass.toCharArray());
        } catch (KeyStoreException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private List<PublicKey> getTrustStore(String name, String trustStoreName, String keyStorePass) {
        List<PublicKey> trustedPublicKeyList = new ArrayList<PublicKey>();
        trustedSigners = new ArrayList<String>();
        File trustStoreFile = new File(getInstanceDir(name), trustStoreName);
        try {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(trustStoreFile), keyStorePass.toCharArray());
            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                trustedSigners.add(alias);
                PublicKey publicKey = trustStore.getCertificate(alias).getPublicKey();
                trustedPublicKeyList.add(publicKey);
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(InstanceConfig.class.getName()).log(Level.SEVERE, null, ex);
        }
        return trustedPublicKeyList;
    }

    private void getInstanceData() {
        instanceMap = new HashMap<String, Instance>();
        instanceKeyStoreMap = new HashMap<String, NamedKeyStore>();
        trustedPublicKeyMap = new HashMap<String, List<PublicKey>>();
        List<String> instanceNames = instances.getInstanceNames();
        for (String name : instanceNames) {
            File instanceFile = getInstanceFile(name);
            File instanceDir = getInstanceDir(name);
            String instanceJson = new String(FileOps.readBinaryFile(instanceFile), Charset.forName("UTF-8"));
            Instance instance = gson.fromJson(instanceJson, Instance.class);
            instanceMap.put(name, instance);

            //get keystore
            NamedKeyStore ks = new NamedKeyStore(instance.getKeyStoreName(), instance.getKeyStorePass().toCharArray(), instanceDir.getAbsolutePath());
            instanceKeyStoreMap.put(name, ks);

            //get trusted public keys
            trustedPublicKeyMap.put(name, getTrustStore(name, instance.getTrustStoreName(), instance.getTrustStorePass()));
        }
    }

    private void getInstancesData() {
        String instancesJson = new String(FileOps.readBinaryFile(instancesFile), Charset.forName("UTF-8"));
        instances = gson.fromJson(instancesJson, Instances.class);
        instancesKeyStore = new NamedKeyStore(instances.getMetaDataSignerKeyStore(), instances.getMetaDataSignerPass().toCharArray(), instancesDir);

    }

    public String getEntityIdInstanceName(String entityID) {
        for (String instanceName: instances.getInstanceNames()){
            Instance inst = instanceMap.get(instanceName);
            if (inst.getEntityId().equalsIgnoreCase(entityID)){
                return instanceName;
            }
        }
        return null;
    }
}
