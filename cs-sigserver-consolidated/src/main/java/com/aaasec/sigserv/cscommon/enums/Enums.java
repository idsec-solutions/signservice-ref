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
package com.aaasec.sigserv.cscommon.enums;

import java.util.HashMap;

/**
 * Enumerations and data maps
 */
public class Enums {

    public static final HashMap<String, String> digestNames = new HashMap<String, String>();
    public static final HashMap<String, String> algorithmNames = new HashMap<String, String>();
    public static final HashMap<String, String> sigAlgorithmNames = new HashMap<String, String>();
    public static final HashMap<String, String> pkAlgorithmNames = new HashMap<String, String>();
    public static final HashMap<String, String> allowedDigests = new HashMap<String, String>();
//    public static final HashMap<String, String> contextAttributes = new HashMap<String, String>();
    public static final HashMap<String, String> idAttributes = new HashMap<String, String>();

    static {
        digestNames.put("1.2.840.113549.2.5", "MD5");
        digestNames.put("1.2.840.113549.2.2", "MD2");
        digestNames.put("1.3.14.3.2.26", "SHA1");
        digestNames.put("2.16.840.1.101.3.4.2.4", "SHA224");
        digestNames.put("2.16.840.1.101.3.4.2.1", "SHA256");
        digestNames.put("2.16.840.1.101.3.4.2.2", "SHA384");
        digestNames.put("2.16.840.1.101.3.4.2.3", "SHA512");
        digestNames.put("1.3.36.3.2.2", "RIPEMD128");
        digestNames.put("1.3.36.3.2.1", "RIPEMD160");
        digestNames.put("1.3.36.3.2.3", "RIPEMD256");
        digestNames.put("1.2.840.113549.1.1.4", "MD5");
        digestNames.put("1.2.840.113549.1.1.2", "MD2");
        digestNames.put("1.2.840.113549.1.1.5", "SHA1");
        digestNames.put("1.2.840.113549.1.1.14", "SHA224");
        digestNames.put("1.2.840.113549.1.1.11", "SHA256");
        digestNames.put("1.2.840.113549.1.1.12", "SHA384");
        digestNames.put("1.2.840.113549.1.1.13", "SHA512");
        digestNames.put("1.2.840.113549.2.5", "MD5");
        digestNames.put("1.2.840.113549.2.2", "MD2");
        digestNames.put("1.2.840.10040.4.3", "SHA1");
        digestNames.put("2.16.840.1.101.3.4.3.1", "SHA224");
        digestNames.put("2.16.840.1.101.3.4.3.2", "SHA256");
        digestNames.put("2.16.840.1.101.3.4.3.3", "SHA384");
        digestNames.put("2.16.840.1.101.3.4.3.4", "SHA512");
        digestNames.put("1.3.36.3.3.1.3", "RIPEMD128");
        digestNames.put("1.3.36.3.3.1.2", "RIPEMD160");
        digestNames.put("1.3.36.3.3.1.4", "RIPEMD256");

        algorithmNames.put("1.2.840.113549.1.1.1", "RSA");
        algorithmNames.put("1.2.840.10040.4.1", "DSA");
        algorithmNames.put("1.2.840.113549.1.1.2", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.4", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.5", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.14", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.11", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.12", "RSA");
        algorithmNames.put("1.2.840.113549.1.1.13", "RSA");
        algorithmNames.put("1.2.840.10040.4.3", "DSA");
        algorithmNames.put("2.16.840.1.101.3.4.3.1", "DSA");
        algorithmNames.put("2.16.840.1.101.3.4.3.2", "DSA");
        algorithmNames.put("1.3.36.3.3.1.3", "RSA");
        algorithmNames.put("1.3.36.3.3.1.2", "RSA");
        algorithmNames.put("1.3.36.3.3.1.4", "RSA");

        pkAlgorithmNames.put("1.2.840.113549.1.1.1", "RSA");
        pkAlgorithmNames.put("1.2.840.10040.4.1", "DSA");

        sigAlgorithmNames.put("1.2.840.113549.1.1.2", "RSA with MD2");
        sigAlgorithmNames.put("1.2.840.113549.1.1.4", "RSA with MD5");
        sigAlgorithmNames.put("1.2.840.113549.1.1.5", "RSA with SHA1");
        sigAlgorithmNames.put("1.2.840.113549.1.1.14", "RSA with SHA224");
        sigAlgorithmNames.put("1.2.840.113549.1.1.11", "RSA with SHA256");
        sigAlgorithmNames.put("1.2.840.113549.1.1.12", "RSA with SHA384");
        sigAlgorithmNames.put("1.2.840.113549.1.1.13", "RSA with SHA512");
        sigAlgorithmNames.put("1.2.840.10040.4.3", "DSA with SHA1");
        sigAlgorithmNames.put("2.16.840.1.101.3.4.3.1", "DSA with SHA224");
        sigAlgorithmNames.put("2.16.840.1.101.3.4.3.2", "DSA with SHA256");
        sigAlgorithmNames.put("1.3.36.3.3.1.3", "RSA with RIPEMD128");
        sigAlgorithmNames.put("1.3.36.3.3.1.2", "RSA with RIPEMD160");
        sigAlgorithmNames.put("1.3.36.3.3.1.4", "RSA with RIPEMD256");

        allowedDigests.put("MD5", "1.2.840.113549.2.5");
        allowedDigests.put("MD2", "1.2.840.113549.2.2");
        allowedDigests.put("SHA1", "1.3.14.3.2.26");
        allowedDigests.put("SHA224", "2.16.840.1.101.3.4.2.4");
        allowedDigests.put("SHA256", "2.16.840.1.101.3.4.2.1");
        allowedDigests.put("SHA384", "2.16.840.1.101.3.4.2.2");
        allowedDigests.put("SHA512", "2.16.840.1.101.3.4.2.3");
        allowedDigests.put("MD-5", "1.2.840.113549.2.5");
        allowedDigests.put("MD-2", "1.2.840.113549.2.2");
        allowedDigests.put("SHA-1", "1.3.14.3.2.26");
        allowedDigests.put("SHA-224", "2.16.840.1.101.3.4.2.4");
        allowedDigests.put("SHA-256", "2.16.840.1.101.3.4.2.1");
        allowedDigests.put("SHA-384", "2.16.840.1.101.3.4.2.2");
        allowedDigests.put("SHA-512", "2.16.840.1.101.3.4.2.3");
        allowedDigests.put("RIPEMD128", "1.3.36.3.2.2");
        allowedDigests.put("RIPEMD-128", "1.3.36.3.2.2");
        allowedDigests.put("RIPEMD160", "1.3.36.3.2.1");
        allowedDigests.put("RIPEMD-160", "1.3.36.3.2.1");
        allowedDigests.put("RIPEMD256", "1.3.36.3.2.3");
        allowedDigests.put("RIPEMD-256", "1.3.36.3.2.3");

//        contextAttributes.put("AuthType", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
//        contextAttributes.put("Shib-Identity-Provider", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
//        contextAttributes.put("Shib-Application-ID", "urn:se:elegnamnden:2012:centralsig:1.0:auth-context:application-id");
//        contextAttributes.put("Shib-Session-ID", "urn:se:elegnamnden:2012:centralsig:1.0:auth-context:session-id");
//        contextAttributes.put("Shib-Authentication-Instant", "urn:se:elegnamnden:2012:centralsig:1.0:auth-context:authentication-instant");
//        contextAttributes.put("Shib-Authentication-Method", "urn:se:elegnamnden:2012:centralsig:1.0:auth-context:authentication-method");
//        contextAttributes.put("Shib-AuthnContext-Class", "urn:se:elegnamnden:2012:centralsig:1.0:auth-context:authn-context-class");
//        contextAttributes.put("Shib-AuthnContext-Decl", "urn:se:elegnamnden:2012:centralsig:1.0:auth-context:authn-context-decl");

        idAttributes.put("cn", "2.5.4.3");
        idAttributes.put("sn", "2.5.4.4");
        idAttributes.put("givenName", "2.5.4.42");
        idAttributes.put("mail", "0.9.2342.19200300.100.1.3");
        idAttributes.put("telephoneNumber", "2.5.4.20");
        idAttributes.put("title", "2.5.4.12");
        idAttributes.put("initials", "2.5.4.43)");
        idAttributes.put("description", "2.5.4.13");
        idAttributes.put("departmentNumber", "2.16.840.1.113730.3.1.2");
        idAttributes.put("employeeNumber", "2.16.840.1.113730.3.1.3");
        idAttributes.put("employeeType", "2.16.840.1.113730.3.1.4");
        idAttributes.put("preferredLanguage", "2.16.840.1.113730.3.1.39");
        idAttributes.put("displayName", "2.16.840.1.113730.3.1.241");
        idAttributes.put("street", "2.5.4.9");
        idAttributes.put("postOfficeBox", "2.5.4.18");
        idAttributes.put("postalCode", "2.5.4.17");
        idAttributes.put("st", "2.5.4.8");
        idAttributes.put("l", "2.5.4.7");
        idAttributes.put("country", "2.5.4.6");
        idAttributes.put("o", "2.5.4.10");
        idAttributes.put("ou", "2.5.4.11");
        idAttributes.put("norEduPersonNIN", "1.3.6.1.4.1.2428.90.1.5");
        idAttributes.put("mobileTelephoneNumber", "0.9.2342.19200300.100.1.41");
        idAttributes.put("personalIdentityNumber", "1.2.752.29.4.13");
        idAttributes.put("persistent-id", "1.3.6.1.4.1.5923.1.1.1.10");
        idAttributes.put("provisionalIdLeg", "1.3.6.1.4.1.40169.2.1");
        idAttributes.put("pidQualityLeg", "1.3.6.1.4.1.40169.2.2");
        idAttributes.put("provisionalId", "1.2.752.201.3.4");
        idAttributes.put("pidQuality", "1.2.752.201.3.5");
        idAttributes.put("orgAffiliation", "1.2.752.201.3.1");
        idAttributes.put("eppn", "1.3.6.1.4.1.5923.1.1.1.6");
        idAttributes.put("eIDASPersonIdentifier", "1.2.752.201.3.7");
    }

//    public enum Attribute {
//
//        cn("2.5.4.3"),
//        sn("2.5.4.4"),
//        givenName("2.5.4.42"),
//        mail("0.9.2342.19200300.100.1.3"),
//        telephoneNumber("2.5.4.20"),
//        title("2.5.4.12"),
//        initials("2.5.4.43)"),
//        description("2.5.4.13"),
//        departmentNumber("2.16.840.1.113730.3.1.2"),
//        employeeNumber("2.16.840.1.113730.3.1.3"),
//        employeeType("2.16.840.1.113730.3.1.4"),
//        preferredLanguage("2.16.840.1.113730.3.1.39"),
//        displayName("2.16.840.1.113730.3.1.241"),
//        street("2.5.4.9"),
//        postOfficeBox("2.5.4.18"),
//        postalCode("2.5.4.17"),
//        st("2.5.4.8"),
//        l("2.5.4.7"),
//        o("2.5.4.10"),
//        ou("2.5.4.11"),
//        norEduPersonNIN("1.3.6.1.4.1.2428.90.1.5"),
//        mobileTelephoneNumber("0.9.2342.19200300.100.1.41"),
//        personalIdentityNumber("1.2.752.29.4.13"),
//        persistent_id("1.3.6.1.4.1.5923.1.1.1.10");
//        public final String oid;
//
//        private Attribute(String oid) {
//            this.oid = oid;
//        }
//
//        public String getOid() {
//            return oid;
//        }                
//    }
    public enum OldResponseCode {

        OK("101", "Successful"),
        SigError("201", "Bad Signature"),
        Malformed("211", "Malformed request"),
        Replay("221", "Replay of old request"),
        Old("222", "Request is to old"),
        IllegalTime("223", "Illegal request time"),
        responseError("301", "Unable to create response"),
        signError("302", "Error when trying to sign as requested"),
        noSignTask("303", "User authentication response does not match any present sign task"),
        userMismatch("304", "The authenticated user does not match the request"),
        expiredRequest("305", "The request is not within it's validity time");
        private final String code;
        private final String message;

        private OldResponseCode(String code, String message) {
            this.code = code;
            this.message = message;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }
    }

    public enum SCResponseCodeMinor {
        epired("http://id.elegnamnden.se/sig-status/1.0/req-expired"),
        userMismatch("http://id.elegnamnden.se/sig-status/1.0/user-mismatch"),
        unsupportedLoa("http://id.elegnamnden.se/sig-status/1.0/unsupported-loa"),
        sigmessageError("http://id.elegnamnden.se/sig-status/1.0/sigmessage-error"),
        userCancel("http://id.elegnamnden.se/sig-status/1.0/user-cancel"),
        absent(null);

        private final String code;

        SCResponseCodeMinor(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }
    }


    public enum ResponseCodeMajor {

        Success("urn:oasis:names:tc:dss:1.0:resultmajor:Success", "Successful"),
        BadRequest("urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError", "Bad Request"),
        SigCreationError("urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError", "Signature service faild to create the requested signature"),
        InsufficientInfo("urn:oasis:names:tc:dss:1.0:resultmajor:InsufficientInformation", "Insufficient Information in the request");
        private final String code;
        private final String message;

        private ResponseCodeMajor(String code, String message) {
            this.code = code;
            this.message = message;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }
    }

    public enum ShibAttribute {

        AuthType("AuthType"),
        IdentityProvider("Shib-Identity-Provider"),
        ApplicationID("Shib-Application-ID"),
        SessionId("Shib-Session-ID"),
        AuthInstant("Shib-Authentication-Instant"),
        ContextClassRef("Shib-AuthnContext-Class");
        private String attrName;

        private ShibAttribute(String attrName) {
            this.attrName = attrName;
        }

        public static ShibAttribute getAttributeByName(String attrName) {
            for (ShibAttribute id : ShibAttribute.values()) {
                if (id.getAttrName().equals(attrName)) {
                    return id;
                }
            }
            return null;
        }

        public String getAttrName() {
            return attrName;
        }

    }
}
