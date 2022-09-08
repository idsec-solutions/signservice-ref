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

import com.aaasec.sigserv.xmlsign.registry.Algorithm;

/**
 * An extension to the {@link com.aaasec.sigserv.xmlsign.registry.Algorithm} interface that also gives the JOSE representation of the algorithm.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface JoseAlgorithm extends Algorithm {

  /**
   * Gets the JOSE (Javascript Object Signing and Encryption) algorithm representation.
   * 
   * @return the JOSE algorithm, or null if no JOSE representation for the algorithm exists
   */
  com.nimbusds.jose.Algorithm getJoseAlgorithm();
  
}
