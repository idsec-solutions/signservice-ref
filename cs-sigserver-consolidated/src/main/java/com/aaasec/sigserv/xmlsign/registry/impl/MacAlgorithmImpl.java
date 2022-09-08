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
import com.aaasec.sigserv.xmlsign.registry.MacAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.MessageDigestAlgorithm;

import java.util.Objects;
import java.util.Optional;

/**
 * Implementation class for {@link MacAlgorithm}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class MacAlgorithmImpl extends com.aaasec.sigserv.xmlsign.registry.impl.AbstractJoseAlgorithm implements MacAlgorithm {

  /** The message digest algorithm. */
  private MessageDigestAlgorithm messageDigestAlgorithm;

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
   * @param messageDigestAlgorithm
   *          the message digest algorithm this signature algorithm uses
   */
  public MacAlgorithmImpl(final String uri, final int order, final String jcaName, final JWSAlgorithm joseAlgorithm,
      final MessageDigestAlgorithm messageDigestAlgorithm) {
    super(uri, order, jcaName, joseAlgorithm);
    this.setMessageDigestAlgorithm(messageDigestAlgorithm);
  }

  /**
   * Protected constructor used by builder.
   *
   * @param uri
   *          the algorithm URI
   */
  protected MacAlgorithmImpl(final String uri) {
    super(uri);
  }

  /**
   * Creates a builder.
   *
   * @param uri
   *          the algorithm URI
   * @return the builder
   */
  public static MacAlgorithmBuilder builder(final String uri) {
    return new MacAlgorithmBuilder(uri);
  }

  /** {@inheritDoc} */
  @Override
  public MessageDigestAlgorithm getMessageDigestAlgorithm() {
    return this.messageDigestAlgorithm;
  }

  /**
   * Sets the message digest algorithm.
   *
   * @param messageDigestAlgorithm
   *          the digest algorithm
   */
  protected void setMessageDigestAlgorithm(final MessageDigestAlgorithm messageDigestAlgorithm) {
    this.messageDigestAlgorithm = Objects.requireNonNull(messageDigestAlgorithm, "messageDigestAlgorithm must be set");
    if (this.messageDigestAlgorithm.isBlacklisted()) {
      this.setBlacklisted(true);
    }
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(this.messageDigestAlgorithm);
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
    if (!(obj instanceof MacAlgorithmImpl)) {
      return false;
    }
    final MacAlgorithmImpl other = (MacAlgorithmImpl) obj;
    return Objects.equals(this.messageDigestAlgorithm, other.messageDigestAlgorithm);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s, message-digest-algorithm='%s'",
      super.toString(), Optional.ofNullable(this.messageDigestAlgorithm).map(MessageDigestAlgorithm::getUri).orElse("-"));
  }

  /**
   * Builder for {@link MacAlgorithm} objects.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  public static class MacAlgorithmBuilder
      extends AbstractJoseAlgorithmBuilder<MacAlgorithmImpl, MacAlgorithmBuilder> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public MacAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /**
     * Sets the message digest algorithm.
     *
     * @param messageDigestAlgorithm
     *          the digest algorithm
     * @return the builder
     */
    public MacAlgorithmBuilder messageDigestAlgorithm(final MessageDigestAlgorithm messageDigestAlgorithm) {
      this.getAlgorithm().setMessageDigestAlgorithm(messageDigestAlgorithm);
      return this.getBuilder();
    }

    /** {@inheritDoc} */
    @Override
    protected void assertCorrect() throws IllegalArgumentException {
      super.assertCorrect();
      if (this.getAlgorithm().getMessageDigestAlgorithm() == null) {
        throw new IllegalArgumentException("messageDigestAlgorithm must be set");
      }
    }

    /** {@inheritDoc} */
    @Override
    protected MacAlgorithmBuilder getBuilder() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    protected MacAlgorithmImpl createAlgorithm(final String algorithmUri) {
      return new MacAlgorithmImpl(algorithmUri);
    }

  }

}
