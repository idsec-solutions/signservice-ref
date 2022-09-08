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

import com.aaasec.sigserv.xmlsign.registry.KeyBasedAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.impl.AlgorithmBuilder;

import java.util.Objects;

/**
 * Abstract implementation of an {@link KeyBasedAlgorithm}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractKeyBasedAlgorithm extends com.aaasec.sigserv.xmlsign.registry.impl.AbstractJoseAlgorithm
  implements KeyBasedAlgorithm {

  /** The key type. */
  private String keyType;

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
  public AbstractKeyBasedAlgorithm(final String uri, final int order, final String keyType, final String jcaName,
      final com.nimbusds.jose.Algorithm joseAlgorithm) {
    super(uri, order, jcaName, joseAlgorithm);
    this.setKeyType(keyType);
  }

  /**
   * Protected constructor used by builders.
   *
   * @param uri
   *          the algorithm URI
   */
  protected AbstractKeyBasedAlgorithm(final String uri) {
    super(uri);
  }

  /** {@inheritDoc} */
  @Override
  public String getKeyType() {
    return this.keyType;
  }

  /**
   * Sets the "key type" for the algorithm.
   *
   * @param keyType
   *          the key type
   */
  protected void setKeyType(final String keyType) {
    this.keyType = Objects.requireNonNull(keyType, "keyType must be set");
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(this.keyType);
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (!(obj instanceof AbstractKeyBasedAlgorithm)) {
      return false;
    }
    final AbstractKeyBasedAlgorithm other = (AbstractKeyBasedAlgorithm) obj;
    return Objects.equals(this.keyType, other.keyType);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s, key-type='%s'", super.toString(), this.keyType);
  }

  /**
   * Abstract builder for {@link KeyBasedAlgorithm} objects.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  protected static abstract class AbstractKeyBasedAlgorithmBuilder<T extends AbstractKeyBasedAlgorithm, B extends AbstractKeyBasedAlgorithmBuilder<T, ? extends AlgorithmBuilder<T>>>
      extends AbstractJoseAlgorithmBuilder<T, B> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public AbstractKeyBasedAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /**
     * Sets the "key type" for the algorithm.
     *
     * @param keyType
     *          the key type
     * @return the builder
     */
    public B keyType(final String keyType) {
      this.getAlgorithm().setKeyType(keyType);
      return this.getBuilder();
    }

    /** {@inheritDoc} */
    @Override
    protected void assertCorrect() throws IllegalArgumentException {
      super.assertCorrect();
      if (this.getAlgorithm().getKeyType() == null) {
        throw new IllegalArgumentException("keyType must be set");
      }
    }

  }

}
