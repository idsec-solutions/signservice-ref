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
package com.aaasec.sigserv.xmlsign.registry;

import com.aaasec.sigserv.xmlsign.registry.MessageDigestAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.SignatureAlgorithm;

import java.security.spec.PSSParameterSpec;

/**
 * Representation of a RSA-PSS signature algorithm.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface RSAPSSSignatureAlgorithm extends SignatureAlgorithm {

  /**
   * Always returns "RSA".
   */
  @Override
  default String getKeyType() {
    return "RSA";
  }

  /**
   * Gets the parameter spec for the RSA-PSS algorithm.
   *
   * @return the PSSParameterSpec
   */
  PSSParameterSpec getParameterSpec();

  /**
   * Gets the Mask Generation Function (MGF) URI. Defaults to {@code http://www.w3.org/2007/05/xmldsig-more#MGF1}.
   *
   * @return the MGF URI
   */
  default String getMGFUri() {
    return "http://www.w3.org/2007/05/xmldsig-more#MGF1";
  }

  /**
   * Gets the digest algorithm for the Mask Generation Function (MGF). Defaults to the same digest algorithm as the
   * signature algorithm.
   *
   * @return the MGF digest algorithm
   */
  default MessageDigestAlgorithm getMGFDigestAlgorithm() {
    return this.getMessageDigestAlgorithm();
  }

}
