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

/**
 * An enum for all algorithm types.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public enum AlgorithmType {

  /** Message digest algorithm. */
  MESSAGE_DIGEST,

  /** Signature algorithm. */
  SIGNATURE,

  /** MAC algorithm. */
  MAC,

  /** Block encryption algorithm. */
  BLOCK_ENCRYPTION,

  /** Key transport algorithm. */
  KEY_TRANSPORT,

  /** Key agreement algorithm. */
  KEY_AGREEMENT,

  /** Symmetric key wrap algorithm. */
  SYMMETRIC_KEY_WRAP;

}
