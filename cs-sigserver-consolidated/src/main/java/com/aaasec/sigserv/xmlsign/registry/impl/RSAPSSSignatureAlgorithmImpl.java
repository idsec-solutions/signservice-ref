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

import com.nimbusds.jose.JWSAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.MessageDigestAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.RSAPSSSignatureAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.SignatureAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.impl.SignatureAlgorithmImpl;

import java.security.spec.PSSParameterSpec;
import java.util.Objects;
import java.util.Optional;

/**
 * Implementation class for {@link RSAPSSSignatureAlgorithm}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class RSAPSSSignatureAlgorithmImpl extends SignatureAlgorithmImpl implements RSAPSSSignatureAlgorithm {

  /** The parameter spec. */
  private PSSParameterSpec parameterSpec;

  /** The MGF URI. */
  private String mgfUri;

  /** The MGF digest algorithm. */
  private MessageDigestAlgorithm mgfDigestAlgorithm;

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
   * @param parameterSpec
   *          the parameter spec
   * @param order
   *          the ordering for the algorithm
   * @param joseAlgorithm
   *          the JOSE algorithm
   * @param messageDigestAlgorithm
   *          the message digest algorithm this signature algorithm uses
   */
  public RSAPSSSignatureAlgorithmImpl(final String uri, final int order, final String keyType,
      final String jcaName, final PSSParameterSpec parameterSpec, final JWSAlgorithm joseAlgorithm,
      final MessageDigestAlgorithm messageDigestAlgorithm) {
    super(uri, order, keyType, jcaName, joseAlgorithm, messageDigestAlgorithm);
  }

  /**
   * Protected constructor used by builder.
   *
   * @param uri
   *          the algorithm URI
   */
  protected RSAPSSSignatureAlgorithmImpl(final String uri) {
    super(uri);
  }

  /**
   * Creates a builder.
   *
   * @param uri
   *          the algorithm URI
   * @return the builder
   */
  public static RSAPSSSignatureAlgorithmBuilder getBuilder(final String uri) {
    return new RSAPSSSignatureAlgorithmBuilder(uri);
  }

  /** {@inheritDoc} */
  @Override
  public PSSParameterSpec getParameterSpec() {
    return this.parameterSpec;
  }

  /**
   * Assigns the parameter spec.
   *
   * @param parameterSpec
   *          the parameter spec
   */
  protected void setParameterSpec(final PSSParameterSpec parameterSpec) {
    this.parameterSpec = parameterSpec;
  }

  /**
   * Gets the MGF URI.
   *
   * @return the MGF URI
   */
  @Override
  public String getMGFUri() {
    return Optional.ofNullable(this.mgfUri).orElse(RSAPSSSignatureAlgorithm.super.getMGFUri());
  }

  /**
   * Assigns the MGF URI. If not assigned, the default given by {@link RSAPSSSignatureAlgorithm#getMGFUri()} is used.
   *
   * @param mgfUri
   *          the MGF URI
   */
  public void setMGFUri(final String mgfUri) {
    this.mgfUri = mgfUri;
  }

  /**
   * Gets the MGF digest algorithm.
   *
   * @return the MGF digest algorithm
   */
  @Override
  public MessageDigestAlgorithm getMGFDigestAlgorithm() {
    return Optional.ofNullable(this.mgfDigestAlgorithm).orElse(RSAPSSSignatureAlgorithm.super.getMGFDigestAlgorithm());
  }

  /**
   * Assigns the MGF digest algorithm. If not assigned, {@link SignatureAlgorithm#getMessageDigestAlgorithm()} will be
   * used.
   *
   * @param mgfDigestAlgorithm
   *          the MGF digest algorithm
   */
  public void setMGFDigestAlgorithm(final MessageDigestAlgorithm mgfDigestAlgorithm) {
    this.mgfDigestAlgorithm = mgfDigestAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(this.mgfDigestAlgorithm, this.mgfUri);
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
    if (!(obj instanceof RSAPSSSignatureAlgorithmImpl)) {
      return false;
    }
    final RSAPSSSignatureAlgorithmImpl other = (RSAPSSSignatureAlgorithmImpl) obj;
    return Objects.equals(this.mgfDigestAlgorithm, other.mgfDigestAlgorithm) && Objects.equals(this.mgfUri, other.mgfUri);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuffer sb = new StringBuffer(super.toString());
    if (this.mgfUri != null) {
      sb.append(", mgf-uri='").append(this.mgfUri).append("'");
    }
    if (this.mgfDigestAlgorithm != null) {
      sb.append(", mgf-digest-uri='").append(this.mgfDigestAlgorithm.getUri()).append("'");
    }
    return sb.toString();
  }

  /**
   * Abstract builder for {@link RSAPSSSignatureAlgorithm}.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  public static class RSAPSSSignatureAlgorithmBuilder
      extends AbstractSignatureAlgorithmBuilder<RSAPSSSignatureAlgorithmImpl, RSAPSSSignatureAlgorithmBuilder> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public RSAPSSSignatureAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /**
     * Assigns the parameter spec.
     *
     * @param parameterSpec
     *          the parameter spec
     */
    public RSAPSSSignatureAlgorithmBuilder parameterSpec(final PSSParameterSpec parameterSpec) {
      this.getAlgorithm().setParameterSpec(parameterSpec);
      return this.getBuilder();
    }

    /**
     * Assigns the MGF URI.
     *
     * @param mgfUri
     *          the MGF URI
     * @return the builder
     */
    public RSAPSSSignatureAlgorithmBuilder mgfUri(final String mgfUri) {
      this.getAlgorithm().setMGFUri(mgfUri);
      return this.getBuilder();
    }

    /**
     * Assigns the MGF digest algorithm.
     *
     * @param mgfDigestAlgorithm
     *          the MGF digest algorithm
     * @return the builder
     */
    public RSAPSSSignatureAlgorithmBuilder setMGFDigestAlgorithm(final MessageDigestAlgorithm mgfDigestAlgorithm) {
      this.getAlgorithm().setMGFDigestAlgorithm(mgfDigestAlgorithm);
      return this.getBuilder();
    }

    /** {@inheritDoc} */
    @Override
    protected void assertCorrect() throws IllegalArgumentException {
      super.assertCorrect();
      if (this.getAlgorithm().getParameterSpec() == null) {
        throw new IllegalArgumentException("parameterSpec must be set");
      }
    }

    /** {@inheritDoc} */
    @Override
    protected RSAPSSSignatureAlgorithmBuilder getBuilder() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    protected RSAPSSSignatureAlgorithmImpl createAlgorithm(String algorithmUri) {
      return new RSAPSSSignatureAlgorithmImpl(algorithmUri);
    }

  }

}
