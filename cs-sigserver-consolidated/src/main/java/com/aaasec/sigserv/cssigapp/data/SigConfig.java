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
package com.aaasec.sigserv.cssigapp.data;

import com.aaasec.sigserv.cscommon.config.ConfigData;

import java.util.ArrayList;
import java.util.List;

/**
 * Signature service configuration data with default values.
 */
public class SigConfig implements ConfigData {

    private boolean devmode, padesCmsAlgoProtection;
    private int crlValidityHours;
    private String sigServiceBaseUrl;
    private String metadataLocation, metadataCertLocation;
    private int metadataRefreshMinutes;
    private String caCountry, caOrgName, caOrgUnitName, caSerialNumber,
            caCommonName, caFileStorageLocation,
            signatureCaName, serviceName, serviceType, caKsPassword, caKsAlias;
    private List<String> legacyLoaIdPs;
    private int caKeyLength;

    public String getName() {
        return "sig-config";
    }

    public void setDefaults() {
        devmode = true;
        crlValidityHours = 2;
        caCountry = "SE";
        caOrgName = "Dev TEST CA org AB (NOT A REAL ORGANIZATION)";
        caOrgUnitName = "Central Signing Service";
        caSerialNumber = "A123456-7890";
        caCommonName = "#### - EID 2.0 Dev TEST Service";
        sigServiceBaseUrl = "https://eid2csig.konki.se";
        caFileStorageLocation = "/Users/stefan/Sites/sigserver/";
        signatureCaName = "Central Signing CA001";
        metadataLocation = "http://md.esp-meta.se/metadata/feed";
        metadataCertLocation = "/opt/webapp/config/metadata-cert-esens.crt";
        metadataRefreshMinutes = 60;
        serviceName = "Signature Service";
        serviceType = "sc-default";
        padesCmsAlgoProtection = true;
        caKsPassword="topSecret";
        caKsAlias="ca";
        legacyLoaIdPs = new ArrayList<>();
        caKeyLength = 3072;
    }

    public SigConfig() {
    }

    public String getCaCommonName() {
        return caCommonName;
    }

    public void setCaCommonName(String caCommonName) {
        this.caCommonName = caCommonName;
    }

    public String getCaCountry() {
        return caCountry;
    }

    public void setCaCountry(String caCountry) {
        this.caCountry = caCountry;
    }

    public String getCaFileStorageLocation() {
        return caFileStorageLocation;
    }

    public void setCaFileStorageLocation(String caFileStorageLocation) {
        this.caFileStorageLocation = caFileStorageLocation;
    }

    public String getCaOrgName() {
        return caOrgName;
    }

    public void setCaOrgName(String caOrgName) {
        this.caOrgName = caOrgName;
    }

    public String getCaOrgUnitName() {
        return caOrgUnitName;
    }

    public void setCaOrgUnitName(String caOrgUnitName) {
        this.caOrgUnitName = caOrgUnitName;
    }

    public String getCaSerialNumber() {
        return caSerialNumber;
    }

    public void setCaSerialNumber(String caSerialNumber) {
        this.caSerialNumber = caSerialNumber;
    }

    public int getCrlValidityHours() {
        return crlValidityHours;
    }

    public void setCrlValidityHours(int crlValidityHours) {
        this.crlValidityHours = crlValidityHours;
    }

    public boolean isDevmode() {
        return devmode;
    }

    public void setDevmode(boolean devmode) {
        this.devmode = devmode;
    }

    public String getSignatureCaName() {
        return signatureCaName;
    }

    public void setSignatureCaName(String signatureCaName) {
        this.signatureCaName = signatureCaName;
    }

    public String getMetadataLocation() {
        return metadataLocation;
    }

    public void setMetadataLocation(String metadataLocation) {
        this.metadataLocation = metadataLocation;
    }

    public String getMetadataCertLocation() {
        return metadataCertLocation;
    }

    public void setMetadataCertLocation(String metadataCertLocation) {
        this.metadataCertLocation = metadataCertLocation;
    }

    public int getMetadataRefreshMinutes() {
        return metadataRefreshMinutes;
    }

    public void setMetadataRefreshMinutes(int metadataRefreshMinutes) {
        this.metadataRefreshMinutes = metadataRefreshMinutes;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getServiceType() {
        return serviceType;
    }

    public void setServiceType(String serviceType) {
        this.serviceType = serviceType;
    }

    public boolean isPadesCmsAlgoProtection() {
        return padesCmsAlgoProtection;
    }

    public void setPadesCmsAlgoProtection(boolean padesCmsAlgoProtection) {
        this.padesCmsAlgoProtection = padesCmsAlgoProtection;
    }

    public List<String> getLegacyLoaIdPs() {
        return legacyLoaIdPs;
    }

    public void setLegacyLoaIdPs(List<String> legacyLoaIdPs) {
        this.legacyLoaIdPs = legacyLoaIdPs;
    }

    public String getCaKsPassword() {
        return caKsPassword;
    }

    public void setCaKsPassword(String caKsPassword) {
        this.caKsPassword = caKsPassword;
    }

    public String getCaKsAlias() {
        return caKsAlias;
    }

    public void setCaKsAlias(String caKsAlias) {
        this.caKsAlias = caKsAlias;
    }

    public int getCaKeyLength() {
        return caKeyLength;
    }

    public void setCaKeyLength(int caKeyLength) {
        this.caKeyLength = caKeyLength;
    }

    public String getSigServiceBaseUrl() {
        return sigServiceBaseUrl;
    }

    public void setSigServiceBaseUrl(String sigServiceBaseUrl) {
        this.sigServiceBaseUrl = sigServiceBaseUrl;
    }
}
