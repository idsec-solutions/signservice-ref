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
package com.aaasec.sigserv.cscommon;

import java.text.SimpleDateFormat;

/**
 * Constants
 */
public interface Constants {

    String LF = System.getProperty("line.separator");
    String PROTOCOL_PROFILE = "http://id.elegnamnden.se/csig/1.1/dss-ext/profile";
    String PROTOCOL_BINDING = "POST/XML/1.0";
    String EID2_PROTOCOL_VERSION = "1.1";
    String CURRENT_EID2_PROTOCOL_VERSION = "1.4";
    /**
     * The maximum +- tolerance in milliseconds between claimed signing time and the current time of the signature server
     */
    public static final long MAX_SIG_TIME_TOLERANCE = 1000*60*5;  // +- 5 minutes tolerance
    /**
     * Privately defined Mime type for CMS Signed attributes 
     */
    public static final String CMS_SIGNED_ATTRIBUTES_MIME_TYPE = "application/cms-signed-attributes";
    /**
     * Identifying keys for Pdf view capable user agents.
     */
    public static final String[][] PDF_VIEW_USER_AGENT_KEYS = new String[][]{
        new String[]{"Mac","Safari"},
        new String[]{"Chrome"}
    };
    
    /**
     * Simple Date format "yyyy-MM-dd HH:mm:ss"
     */
    public static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    /**
     * Simple Date format "yyyy-MM-dd"
     */
    public static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    public static final String[] SHIB_ATTRIBUTE_IDs = new String[]{"Shib-Application-ID", "Shib-Session-ID", "Shib-Identity-Provider", "Shib-Authentication-Instant",
        "Shib-Authentication-Method", "Shib-AuthnContext-Class", "Shib-AuthnContext-Decl"};
    public static final String[] ID_ATTRIBUTES = new String[]{"personalIdentityNumber", "persistent-id", "norEduPersonNIN", "mail"};
    public static final String SHIB_ASSERTION_COUNT = "Shib-Assertion-Count";
    public static final String ASSERION_LOC_PREFIX = "Shib-Assertion-0";
    /**
     * Signature algorithms 
     */
    public static final String[] SIGNATURE_ALGORITHMS = new String[]{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"};
    /*
     * Levels of assurance
     */
    public static final String LOA1 = "http://id.elegnamnden.se/loa/1.0/loa1";
    public static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";
    public static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";
    public static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";
    public static final String LOA2SM = "http://id.elegnamnden.se/loa/1.0/loa2-sigmessage";
    public static final String LOA3SM = "http://id.elegnamnden.se/loa/1.0/loa3-sigmessage";
    public static final String LOA4SM = "http://id.elegnamnden.se/loa/1.0/loa4-sigmessage";
    public static final String eIDASlow ="http://id.elegnamnden.se/loa/1.0/eidas-low";
    public static final String eIDASsub="http://id.elegnamnden.se/loa/1.0/eidas-sub";
    public static final String eIDASsubNF="http://id.elegnamnden.se/loa/1.0/eidas-nf-sub";
    public static final String eIDAShigh="http://id.elegnamnden.se/loa/1.0/eidas-high";
    public static final String eIDAShighNF="http://id.elegnamnden.se/loa/1.0/eidas-nf-high";
    public static final String eIDASlowSM="http://id.elegnamnden.se/loa/1.0/eidas-low-sigm";
    public static final String eIDASsubSM="http://id.elegnamnden.se/loa/1.0/eidas-sub-sigm";
    public static final String eIDASsubNFSM="http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm";
    public static final String eIDAShighSM="http://id.elegnamnden.se/loa/1.0/eidas-high-sigm";
    public static final String eIDAShighNFSM="http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm";
    public static final String UNCERTIFIED_LOA3 = "http://id.swedenconnect.se/loa/1.0/uncertified-loa3";
    public static final String UNCERTIFIED_LOA3_SM = "http://id.swedenconnect.se/loa/1.0/uncertified-loa3-sigmessage";
    
   /**
    * Default signature validation trust policy;
    */
    public static final String VALIDATION_POLICY = "All EU Trust Services";
    public static final String VALIDATION_SERVICE_URL_PARAM = "validationServiceUrl";


    /**
     * SAP support constants
     */
    String ENTITY_CATEGORY = "http://macedir.org/entity-category";
    String SCAL2_SERVICE_PROPERTY = "http://id.elegnamnden.se/sprop/1.0/scal2";


}
