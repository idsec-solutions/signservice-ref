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
package com.aaasec.sigserv.cssigapp.ca;

import java.util.ArrayList;
import java.util.List;

/**
 * Certificate path
 */
public class CertPath {

    private List<String> certPath = new ArrayList<String>();

    public CertPath() {
    }

    public CertPath add(String cert) {
        certPath.add(cert);
        return this;
    }

    public String get(int i) {
        try {
            return certPath.get(i);
        } catch (Exception ex) {
            return null;
        }
    }

    public CertPath clear() {
        certPath.clear();
        return this;
    }

    public List<String> getCertPath() {
        return certPath;
    }

    public void setCertPath(List<String> certPath) {
        this.certPath = certPath;
    }
}
