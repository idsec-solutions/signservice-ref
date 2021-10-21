package com.aaasec.sigserv.cssigapp.instances;

/**
 *
 * @author stefan
 */
public class Instance {

    private String entityId;
    private String keyStoreName = "keystore.jks";
    private String keyStorePass;
    private String trustStoreName = "truststore.jks";
    private String trustStorePass;
    private InstanceMetadata instanceMetadata;

    public Instance() {
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }

    public String getKeyStoreName() {
        return keyStoreName;
    }

    public void setKeyStoreName(String keyStoreName) {
        this.keyStoreName = keyStoreName;
    }

    public String getKeyStorePass() {
        return keyStorePass;
    }

    public void setKeyStorePass(String keyStorePass) {
        this.keyStorePass = keyStorePass;
    }

    public String getTrustStoreName() {
        return trustStoreName;
    }

    public void setTrustStoreName(String trustStoreName) {
        this.trustStoreName = trustStoreName;
    }

    public String getTrustStorePass() {
        return trustStorePass;
    }

    public void setTrustStorePass(String trustStorePass) {
        this.trustStorePass = trustStorePass;
    }

    public InstanceMetadata getInstanceMetadata() {
        return instanceMetadata;
    }

    public void setInstanceMetadata(InstanceMetadata instanceMetadata) {
        this.instanceMetadata = instanceMetadata;
    }

    
}
