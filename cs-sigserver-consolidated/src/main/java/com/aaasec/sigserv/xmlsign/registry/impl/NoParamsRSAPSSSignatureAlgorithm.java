/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.aaasec.sigserv.xmlsign.registry.impl;

import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.aaasec.sigserv.xmlsign.registry.MessageDigestAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.impl.RSAPSSSignatureAlgorithmImpl;

/**
 * Handles the special case where we represent RSA-PSS without any parameters.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NoParamsRSAPSSSignatureAlgorithm extends RSAPSSSignatureAlgorithmImpl {

  /**
   * Constructor.
   */
  public NoParamsRSAPSSSignatureAlgorithm() {
    super("http://www.w3.org/2007/05/xmldsig-more#rsa-pss");
//    super(XMLSignature.ALGO_ID_SIGNATURE_RSA_PSS);
    this.setKeyType("RSA");
    this.setOrder(Integer.MAX_VALUE);
    this.setJcaName("RSASSA-PSS");
  }

  /**
   * Always returns {@code null}.
   */
  @Override
  public String getMGFUri() {
    return null;
  }

  /**
   * No AlgorithmIdentifier is valid for this special case. Only the OID.
   */
  @Override
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return null;
  }

  /**
   * Always returns {@code null}.
   */
  @Override
  public MessageDigestAlgorithm getMGFDigestAlgorithm() {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("uri='%s', jca-name='%s', key-type='%s', blacklisted='%s'",
      this.getUri(), this.getJcaName(), this.getKeyType(), this.isBlacklisted());
  }

}
