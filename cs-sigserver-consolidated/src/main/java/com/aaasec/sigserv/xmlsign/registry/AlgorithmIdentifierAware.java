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

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.aaasec.sigserv.xmlsign.registry.Algorithm;

/**
 * Interface that tells that an {@link Algorithm} instance also represents an ASN.1 {@code AlgorithmIdentifier}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface AlgorithmIdentifierAware extends Algorithm {

  /**
   * Gets the ASN.1 {@code AlgorithmIdentifier} for the algorithm.
   *
   * @return the AlgorithmIdentifier
   */
  AlgorithmIdentifier getAlgorithmIdentifier();

}
