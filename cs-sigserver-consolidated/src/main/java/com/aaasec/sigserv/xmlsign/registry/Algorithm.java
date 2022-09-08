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

import com.aaasec.sigserv.xmlsign.registry.AlgorithmType;

/**
 * Representation of an algorithm.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface Algorithm {

  /**
   * Gets the URI representation of the algorithm.
   *
   * @return the URI
   */
  String getUri();

  /**
   * Gets the algorithm type.
   *
   * @return the type
   */
  AlgorithmType getType();

  /**
   * Gets the JCA (Java Cryptography Architecture) name.
   *
   * @return the JCA name
   */
  String getJcaName();

  /**
   * Gets the order for an algorithm where a lower order is seen as more preferable than an algorithm with a higher
   * ordering. The ordering is relative to algorithms of the same type, and also other critera such as key or key
   * length material.
   *
   * @return a positive integer
   */
  int getOrder();

  /**
   * Tells whether this algorithm is black-listed, i.e., configured to not be allowed.
   *
   * @return true if the algorithm is black-listed and false otherwise
   */
  boolean isBlacklisted();

}
