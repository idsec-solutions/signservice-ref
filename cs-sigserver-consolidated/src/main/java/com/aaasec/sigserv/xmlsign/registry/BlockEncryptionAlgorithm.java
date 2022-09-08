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
import com.aaasec.sigserv.xmlsign.registry.EncryptionAlgorithm;

/**
 * Representation of a block encryption algorithm.
 * 
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface BlockEncryptionAlgorithm extends EncryptionAlgorithm {

  /**
   * Gets the number of bits for the initialization vector (IV).
   * 
   * @return the IV length
   */
  int getIvLength();

  /** {@inheritDoc} */
  @Override
  default AlgorithmType getType() {
    return AlgorithmType.BLOCK_ENCRYPTION;
  }

}
