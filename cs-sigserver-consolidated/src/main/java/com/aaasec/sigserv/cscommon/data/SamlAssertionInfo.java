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
package com.aaasec.sigserv.cscommon.data;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * SAML Assertion information.
 */
public class SamlAssertionInfo {
    
    private AuthContextInfo authContextInfo = new AuthContextInfo();
    private List<IdAttribute> idAttributes = new ArrayList<IdAttribute>();;
    
    public SamlAssertionInfo() {
    }
    
    public IdAttribute addIdAttribute() {
        IdAttribute idAttr = new IdAttribute();
        idAttributes.add(idAttr);
        return idAttr;
    }

    public IdAttribute addIdAttribute(String name, String samlAttr, String attrValue, CertNameType certNameType, String certRef) {
        IdAttribute idAttr = new IdAttribute(name, samlAttr, attrValue, certNameType, certRef);
        idAttributes.add(idAttr);
        return idAttr;
    }

    public AuthContextInfo getAuthContextInfo() {
        return authContextInfo;
    }

    public void setAuthContextInfo(AuthContextInfo authContextInfo) {
        this.authContextInfo = authContextInfo;
    }

    public List<IdAttribute> getIdAttributes() {
        return idAttributes;
    }

    public void setIdAttributes(List<IdAttribute> idAttributes) {
        this.idAttributes = idAttributes;
    }    
    
    public class AuthContextInfo {
        
        private String identityProvider;
        private Date authenticationInstant;
        private String authnContextClassRef;
        private String assertionRef;
        private String serviceID;
        
        public AuthContextInfo(String identityProvider, Date authenticationInstant, String authnContextClassRef, String assertionRef, String serviceID) {
            this.identityProvider = identityProvider;
            this.authenticationInstant = authenticationInstant;
            this.authnContextClassRef = authnContextClassRef;
            this.assertionRef = assertionRef;
            this.serviceID = serviceID;
        }

        public AuthContextInfo() {
        }

        public String getIdentityProvider() {
            return identityProvider;
        }

        public void setIdentityProvider(String identityProvider) {
            this.identityProvider = identityProvider;
        }

        public Date getAuthenticationInstant() {
            return authenticationInstant;
        }

        public void setAuthenticationInstant(Date authenticationInstant) {
            this.authenticationInstant = authenticationInstant;
        }

        public String getAuthnContextClassRef() {
            return authnContextClassRef;
        }

        public void setAuthnContextClassRef(String authnContextClassRef) {
            this.authnContextClassRef = authnContextClassRef;
        }

        public String getAssertionRef() {
            return assertionRef;
        }

        public void setAssertionRef(String assertionRef) {
            this.assertionRef = assertionRef;
        }

        public String getServiceID() {
            return serviceID;
        }

        public void setServiceID(String serviceID) {
            this.serviceID = serviceID;
        }
        
    }
    
    public class IdAttribute {
        
        private String name;
        private String samlAttr;
        private String attrValue;
        private CertNameType certNameType;
        private String certRef;
        
        public IdAttribute() {
        }
        
        public IdAttribute(String name, String samlAttr, String attrValue, CertNameType certNameType, String certRef) {
            this.name = name;
            this.samlAttr = samlAttr;
            this.attrValue = attrValue;
            this.certNameType = certNameType;
            this.certRef = certRef;
        }
        
        public String getName() {
            return name;
        }
        
        public void setName(String name) {
            this.name = name;
        }
        
        public String getSamlAttr() {
            return samlAttr;
        }
        
        public void setSamlAttr(String samlAttr) {
            this.samlAttr = samlAttr;
        }
        
        public String getAttrValue() {
            return attrValue;
        }
        
        public void setAttrValue(String attrValue) {
            this.attrValue = attrValue;
        }
        
        public CertNameType getCertNameType() {
            return certNameType;
        }
        
        public void setCertNameType(CertNameType certNameType) {
            this.certNameType = certNameType;
        }
        
        public String getCertRef() {
            return certRef;
        }
        
        public void setCertRef(String certRef) {
            this.certRef = certRef;
        }
    }
    
    public enum CertNameType {
        
        rdn,
        san,
        sda;
    }
}
