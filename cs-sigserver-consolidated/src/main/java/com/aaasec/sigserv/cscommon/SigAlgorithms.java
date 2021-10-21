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

import com.aaasec.lib.crypto.xml.XMLSign;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.signature.XMLSignature;

import java.util.Arrays;
import java.util.Optional;

/**
 * Signature Algorithms.
 */
public enum SigAlgorithms {

  RSA(XMLCipher.SHA256, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, "SHA-256", "SHA1withRSA"),
  RSA_PSS(XMLCipher.SHA256, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, "SHA-256", "SHA1withRSA"),
  ECDSA(XMLCipher.SHA256, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, "SHA-256", "SHA1withECDSA"),
  UNSUPPORTED(null, null, null, null);

  private static final int[] sha256Prefix = new int[] { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, 0x05, 0x00, 0x04, 0x20 };
  private final String digestAlgo;
  private final String sigAlgo;
  private final String messageDigestName;
  private final String dummyCertAlgo;

  private SigAlgorithms(String digestAlgo, String sigAlgo, String messageDigestName, String dummyCertAlgo) {
    this.digestAlgo = digestAlgo;
    this.sigAlgo = sigAlgo;
    this.messageDigestName = messageDigestName;
    this.dummyCertAlgo = dummyCertAlgo;
  }

  public String getDigestAlgo() {
    return digestAlgo;
  }

  public String getSigAlgo() {
    return sigAlgo;
  }

  public String getDummyCertAlgo() {
    return dummyCertAlgo;
  }

  public String getMessageDigestName() {
    return messageDigestName;
  }

  public static SigAlgorithms getPreferredAlgoByURI(String algoURI) {
    SigAlgorithms selectedAlgoByURI = getSelectedAlgoByURI(algoURI);
    if (selectedAlgoByURI == SigAlgorithms.UNSUPPORTED) {
      return SigAlgorithms.RSA;
    }
    return selectedAlgoByURI;
  }

  public static SigAlgorithms getSelectedAlgoByURI(String algoURI) {

    Optional<SigAlgorithms> algorithmOptional = Arrays.stream(values())
      .filter(sigAlgorithms -> sigAlgorithms.getSigAlgo() != null && sigAlgorithms.getSigAlgo().equals(algoURI))
      .findFirst();

    return algorithmOptional.isPresent() ? algorithmOptional.get() : SigAlgorithms.UNSUPPORTED;
  }

  public byte[] getPKCS1hash(byte[] hash) {
    byte[] p1Hash;
    if (messageDigestName.equalsIgnoreCase("SHA-256")) {
      int len = hash.length + sha256Prefix.length;
      p1Hash = new byte[len];
      for (int i = 0; i < sha256Prefix.length; i++) {
        p1Hash[i] = (byte) sha256Prefix[i];
      }
      System.arraycopy(hash, 0, p1Hash, sha256Prefix.length, hash.length);
      return p1Hash;
    }
    // add support for other hash algorithms

    return null;
  }
}
