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

import com.aaasec.sigserv.xmlsign.registry.AlgorithmType;
import com.aaasec.sigserv.xmlsign.registry.impl.AbstractEncryptionAlgorithm;

/**
 * Implementation class for symmetric key wrap algorithms.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SymmetricKeyWrapImpl extends AbstractEncryptionAlgorithm {

  /**
   * Constructor.
   *
   * @param uri
   *          the algorithm URI
   * @param order
   *          the ordering for the algorithm
   * @param keyType
   *          the key type
   * @param keyLength
   *          the key length in bits
   * @param jcaName
   *          the JCA name
   * @param joseAlgorithm
   *          the JOSE algorithm (may be null)
   */
  public SymmetricKeyWrapImpl(final String uri, final int order, final String keyType,
      final int keyLength, final String jcaName, final com.nimbusds.jose.Algorithm joseAlgorithm) {
    super(uri, order, keyType, keyLength, jcaName, joseAlgorithm);
  }

  /**
   * Protected constructor used by builder.
   *
   * @param uri
   *          the algorithm URI
   */
  protected SymmetricKeyWrapImpl(final String uri) {
    super(uri);
  }

  /**
   * Creates a builder.
   *
   * @param uri
   *          the algorithm URI
   * @return the builder
   */
  public static SymmetricKeyWrapBuilder builder(final String uri) {
    return new SymmetricKeyWrapBuilder(uri);
  }

  /** {@inheritDoc} */
  @Override
  public final AlgorithmType getType() {
    return AlgorithmType.SYMMETRIC_KEY_WRAP;
  }

  /**
   * Builder for creating symmetric key wrap algorithms.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  public static class SymmetricKeyWrapBuilder
      extends AbstractEncryptionAlgorithmBuilder<SymmetricKeyWrapImpl, SymmetricKeyWrapBuilder> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public SymmetricKeyWrapBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /** {@inheritDoc} */
    @Override
    protected SymmetricKeyWrapBuilder getBuilder() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    protected SymmetricKeyWrapImpl createAlgorithm(final String algorithmUri) {
      return new SymmetricKeyWrapImpl(algorithmUri);
    }

  }

}
