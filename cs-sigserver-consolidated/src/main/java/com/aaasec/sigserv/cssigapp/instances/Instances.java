/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.instances;

import java.util.List;

/**
 *
 * @author stefan
 */
public class Instances {

    private String metaDataSignerKeyStore = "metaSignerKeyStore.jks";
    private String metaDataSignerPass;
    private List<String> instanceNames;
    private int metadataCacheDurationMinutes;
    private int metadataValidityMinutes;

    public Instances() {
    }

    public String getMetaDataSignerKeyStore() {
        return metaDataSignerKeyStore;
    }

    public void setMetaDataSignerKeyStore(String metaDataSignerKeyStore) {
        this.metaDataSignerKeyStore = metaDataSignerKeyStore;
    }

    public String getMetaDataSignerPass() {
        return metaDataSignerPass;
    }

    public void setMetaDataSignerPass(String metaDataSignerPass) {
        this.metaDataSignerPass = metaDataSignerPass;
    }

    public List<String> getInstanceNames() {
        return instanceNames;
    }

    public void setInstanceNames(List<String> instanceNames) {
        this.instanceNames = instanceNames;
    }

    public int getMetadataCacheDurationMinutes() {
        return metadataCacheDurationMinutes;
    }

    public void setMetadataCacheDurationMinutes(int metadataCacheDurationMinutes) {
        this.metadataCacheDurationMinutes = metadataCacheDurationMinutes;
    }

    public int getMetadataValidityMinutes() {
        return metadataValidityMinutes;
    }

    public void setMetadataValidityMinutes(int metadataValidityMinutes) {
        this.metadataValidityMinutes = metadataValidityMinutes;
    }

}
