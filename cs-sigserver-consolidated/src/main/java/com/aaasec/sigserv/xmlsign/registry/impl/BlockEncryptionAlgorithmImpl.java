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
import com.aaasec.sigserv.xmlsign.registry.BlockEncryptionAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.impl.AbstractEncryptionAlgorithm;

import java.util.Objects;

/**
 * Implementation class for {@link BlockEncryptionAlgorithm}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BlockEncryptionAlgorithmImpl extends AbstractEncryptionAlgorithm implements BlockEncryptionAlgorithm {

  /** The IV length. */
  private int ivLength;

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
   * @param ivLength
   *          IV length in bits
   * @param jcaName
   *          the JCA name
   * @param joseAlgorithm
   *          the JOSE algorithm (may be null)
   */
  public BlockEncryptionAlgorithmImpl(final String uri, final int order, final String keyType,
      final int keyLength, final int ivLength, final String jcaName, final Algorithm joseAlgorithm) {
    super(uri, order, keyType, keyLength, jcaName, joseAlgorithm);
    this.setIvLength(ivLength);
  }

  /**
   * Protected constructor used by builder.
   *
   * @param uri
   *          the algorithm URI
   */
  protected BlockEncryptionAlgorithmImpl(final String uri) {
    super(uri);
  }

  /**
   * Creates a builder.
   *
   * @param uri
   *          the algorithm URI
   * @return the builder
   */
  public static BlockEncryptionAlgorithmBuilder builder(final String uri) {
    return new BlockEncryptionAlgorithmBuilder(uri);
  }

  /** {@inheritDoc} */
  @Override
  public int getIvLength() {
    return this.ivLength;
  }

  /**
   * Assigns the IV length.
   *
   * @param ivLength
   *          the IV length
   */
  protected void setIvLength(final int ivLength) {
    this.ivLength = ivLength;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(this.ivLength);
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
    if (!(obj instanceof BlockEncryptionAlgorithmImpl)) {
      return false;
    }
    final BlockEncryptionAlgorithmImpl other = (BlockEncryptionAlgorithmImpl) obj;
    return this.ivLength == other.ivLength;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s, iv-length='%d'", super.toString(), this.ivLength);
  }

  /**
   * Builder for {@link BlockEncryptionAlgorithm} objects.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  public static class BlockEncryptionAlgorithmBuilder extends
      AbstractEncryptionAlgorithmBuilder<BlockEncryptionAlgorithmImpl, BlockEncryptionAlgorithmBuilder> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public BlockEncryptionAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /**
     * Assigns the IV length.
     *
     * @param ivLength
     *          the IV length
     * @return the builder
     */
    public BlockEncryptionAlgorithmBuilder ivLength(final int ivLength) {
      this.getAlgorithm().setIvLength(ivLength);
      return this.getBuilder();
    }

    /** {@inheritDoc} */
    @Override
    protected BlockEncryptionAlgorithmBuilder getBuilder() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    protected BlockEncryptionAlgorithmImpl createAlgorithm(final String algorithmUri) {
      return new BlockEncryptionAlgorithmImpl(algorithmUri);
    }

  }
}
