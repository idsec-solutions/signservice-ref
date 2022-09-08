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

import com.aaasec.sigserv.xmlsign.registry.JoseAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.impl.AlgorithmBuilder;

import java.util.Objects;
import java.util.Optional;

/**
 * Abstract implementation of an {@link JoseAlgorithm}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractJoseAlgorithm extends com.aaasec.sigserv.xmlsign.registry.impl.AbstractAlgorithm
  implements JoseAlgorithm {

  /** The JOSE algorithm. */
  private com.nimbusds.jose.Algorithm joseAlgorithm;

  /**
   * Constructor.
   *
   * @param uri
   *          the algorithm URI
   * @param order
   *          the ordering for the algorithm
   * @param jcaName
   *          the JCA name
   * @param joseAlgorithm
   *          the JOSE algorithm (may be null)
   */
  public AbstractJoseAlgorithm(final String uri, final int order, final String jcaName,
      final com.nimbusds.jose.Algorithm joseAlgorithm) {
    super(uri, order, jcaName);
    this.setJoseAlgorithm(joseAlgorithm);
  }

  /**
   * Protected constructor used by builders.
   *
   * @param uri
   *          the algorithm URI
   */
  protected AbstractJoseAlgorithm(final String uri) {
    super(uri);
  }

  /** {@inheritDoc} */
  @Override
  public com.nimbusds.jose.Algorithm getJoseAlgorithm() {
    return this.joseAlgorithm;
  }

  /**
   * Sets the JOSE algorithm representation for the algorithm.
   *
   * @param joseAlgorithm
   *          the JOSE algorithm
   */
  protected void setJoseAlgorithm(final com.nimbusds.jose.Algorithm joseAlgorithm) {
    this.joseAlgorithm = joseAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(this.joseAlgorithm);
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
    if (!(obj instanceof AbstractJoseAlgorithm)) {
      return false;
    }
    final AbstractJoseAlgorithm other = (AbstractJoseAlgorithm) obj;
    return Objects.equals(this.joseAlgorithm, other.joseAlgorithm);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s, jose-algorithm='%s'", super.toString(),
      Optional.ofNullable(this.joseAlgorithm).map(com.nimbusds.jose.Algorithm::toString).orElse("-"));
  }

  /**
   * Abstract builder for {@link JoseAlgorithm} objects.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  protected static abstract class AbstractJoseAlgorithmBuilder<T extends AbstractJoseAlgorithm, B extends AbstractJoseAlgorithmBuilder<T, ? extends AlgorithmBuilder<T>>>
      extends AbstractAlgorithmBuilder<T, B> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public AbstractJoseAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /**
     * Sets the JOSE algorithm representation for the algorithm.
     *
     * @param joseAlgorithm
     *          the JOSE algorithm
     * @return the builder
     */
    public B joseAlgorithm(final com.nimbusds.jose.Algorithm joseAlgorithm) {
      this.getAlgorithm().setJoseAlgorithm(joseAlgorithm);
      return this.getBuilder();
    }

  }

}
