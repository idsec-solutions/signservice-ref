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

/**
 * Key store constants
 */
public interface CaKeyStoreConstants {
  public final static String RSA_1024         = "RSA.1024";
  public final static String KS_FILEEXT       = ".keystore";
  public final static String CERT_SERIAL_KEY  = "CertSerial";
  public final static String CRL_SERIAL_KEY   = "CRLSerial";
  public final static int ISSUE_EVENT         = 1;
  public final static int REVOKE_EVENT        = 2;
  public final static String POLICY_QCSSCD = "0.4.0.1456.1.1";
  public final static String POLICY_QC = "0.4.0.1456.1.2";
  public final static long YEAR = 31536000000L;
  public final static String[] REV_REASON     = new String[] {"unspecified", "keyCompromise", "cACompromise", 
      "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "not used", "removeFromCRL",
      "privilegeWithdrawn", "aACompromise"};
}
