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
package com.aaasec.sigserv.csdaemon.ca;

import com.aaasec.sigserv.cscommon.config.ConfigData;

/**
 * Configuration data for Root CA
 */
public class RootCaConfig implements ConfigData{
    int keyLength, validityYears;
    String commonName, organizationName, orgUnitName, serialNumber, country, rootKsPassword, rootKsAlias;

    public String getName() {
        return "rootCaConf";
    }
    
    public void setDefaults() {
        keyLength = 4096;
        validityYears = 15;
        commonName = "Dev Central Signing Root Certification Authority";
        organizationName = "Dev Test Org AB (NOT A REAL ORGANIZATION)";
        orgUnitName = "Central Sgining Service";
        serialNumber= "SE123456-7890";
        country = "SE";
        rootKsPassword="topSecret";
        rootKsAlias="root_ca";
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    public String getOrgUnitName() {
        return orgUnitName;
    }

    public void setOrgUnitName(String orgUnitName) {
        this.orgUnitName = orgUnitName;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public int getValidityYears() {
        return validityYears;
    }

    public void setValidityYears(int validityYears) {
        this.validityYears = validityYears;
    }

    public String getRootKsPassword() {
        return rootKsPassword;
    }

    public void setRootKsPassword(String rootKsPassword) {
        this.rootKsPassword = rootKsPassword;
    }

    public String getRootKsAlias() {
        return rootKsAlias;
    }

    public void setRootKsAlias(String rootKsAlias) {
        this.rootKsAlias = rootKsAlias;
    }
}
