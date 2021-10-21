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
package com.aaasec.sigserv.cssigapp.models;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.config.ConfigFactory;
import com.aaasec.sigserv.cssigapp.data.SigConfig;
import com.google.gson.Gson;
import iaik.x509.X509Certificate;
import java.util.List;
import java.util.logging.Logger;

/**
 * Signature server model.
 */
public class SigServerModel implements Constants,ServerConstants {

    private static final Logger LOG = Logger.getLogger(SigServerModel.class.getName());
    private final String dataLocation;
    private List<X509Certificate> spCerts;
    private final Gson gson = new Gson();
    private final boolean devmode;
    private SigConfig conf;

    public SigServerModel(String dataLocation) {
        this.dataLocation = dataLocation;
        ConfigFactory<SigConfig> confFact = new ConfigFactory<SigConfig>(dataLocation, new SigConfig());
        conf = confFact.getConfData();
        devmode = conf.isDevmode();
    }
    
    public SigConfig reloadConf() {
        ConfigFactory<SigConfig> confFact = new ConfigFactory<SigConfig>(dataLocation, new SigConfig());
        conf = confFact.getConfData();        
        return conf;
    }

    public String getDataLocation() {
        return dataLocation;
    }

    public boolean isDevmode() {
        return devmode;
    }

    public Gson getGson() {
        return gson;
    }

    public List<X509Certificate> getSpCerts() {
        return spCerts;
    }

    public void setSpCerts(List<X509Certificate> spCerts) {
        this.spCerts = spCerts;
    }

    public SigConfig getConf() {
        return conf;
    }
    
}
