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
import com.aaasec.sigserv.xmlsign.registry.EncryptionAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.impl.AlgorithmBuilder;

import java.util.Objects;

/**
 * Abstract base class for encryption algorithms.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractEncryptionAlgorithm extends AbstractKeyBasedAlgorithm
  implements EncryptionAlgorithm {

  /** The key length. */
  private int keyLength;

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
  public AbstractEncryptionAlgorithm(final String uri, final int order, final String keyType,
      final int keyLength, final String jcaName, final Algorithm joseAlgorithm) {
    super(uri, order, keyType, jcaName, joseAlgorithm);
    this.setKeyLength(keyLength);
  }

  /**
   * Protected constructor used by builders.
   *
   * @param uri
   *          the algorithm URI
   */
  protected AbstractEncryptionAlgorithm(final String uri) {
    super(uri);
  }

  /** {@inheritDoc} */
  @Override
  public int getKeyLength() {
    return this.keyLength;
  }

  /**
   * Assigns the key length in bits.
   *
   * @param keyLength
   *          the key length in bits
   */
  protected void setKeyLength(final int keyLength) {
    this.keyLength = keyLength;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(this.keyLength);
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
    if (!(obj instanceof AbstractEncryptionAlgorithm)) {
      return false;
    }
    final AbstractEncryptionAlgorithm other = (AbstractEncryptionAlgorithm) obj;
    return this.keyLength == other.keyLength;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s, key-length='%d'", super.toString(), this.keyLength);
  }

  /**
   * Abstract builder for {@link EncryptionAlgorithm} objects.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  protected static abstract class AbstractEncryptionAlgorithmBuilder<T extends AbstractEncryptionAlgorithm, B extends AbstractEncryptionAlgorithmBuilder<T, ? extends AlgorithmBuilder<T>>>
      extends AbstractKeyBasedAlgorithmBuilder<T, B> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public AbstractEncryptionAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /**
     * Sets the key length in bits.
     *
     * @param keyLength
     *          the key length in bits
     * @return the builder
     */
    public B keyLength(final int keyLength) {
      this.getAlgorithm().setKeyLength(keyLength);
      return this.getBuilder();
    }

  }

}
