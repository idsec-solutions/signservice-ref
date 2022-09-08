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

import com.nimbusds.jose.Algorithm;
import com.aaasec.sigserv.xmlsign.registry.KeyTransportAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.impl.AbstractKeyBasedAlgorithm;

/**
 * Implementation class for {@link KeyTransportAlgorithm}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class KeyTransportAlgorithmImpl extends AbstractKeyBasedAlgorithm implements KeyTransportAlgorithm {

  /**
   * Constructor.
   *
   * @param uri
   *          the algorithm URI
   * @param order
   *          the ordering for the algorithm
   * @param keyType
   *          the key type
   * @param jcaName
   *          the JCA name
   * @param joseAlgorithm
   *          the JOSE algorithm (may be null)
   */
  public KeyTransportAlgorithmImpl(final String uri, final int order,
      final String keyType, final String jcaName, final Algorithm joseAlgorithm) {
    super(uri, order, keyType, jcaName, joseAlgorithm);
  }

  /**
   * Protected constructor used by the builder.
   *
   * @param uri
   *          the algorithm URI
   */
  protected KeyTransportAlgorithmImpl(final String uri) {
    super(uri);
  }

  /**
   * Creates a builder.
   *
   * @param uri
   *          the algorithm URI
   * @return the builder
   */
  public static KeyTransportAlgorithmBuilder builder(final String uri) {
    return new KeyTransportAlgorithmBuilder(uri);
  }

  /**
   * Builder for {@link KeyTransportAlgorithm} objects.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  public static class KeyTransportAlgorithmBuilder extends
      AbstractKeyBasedAlgorithmBuilder<KeyTransportAlgorithmImpl, KeyTransportAlgorithmBuilder> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public KeyTransportAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /** {@inheritDoc} */
    @Override
    protected KeyTransportAlgorithmBuilder getBuilder() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    protected KeyTransportAlgorithmImpl createAlgorithm(final String algorithmUri) {
      return new KeyTransportAlgorithmImpl(algorithmUri);
    }

  }

}
