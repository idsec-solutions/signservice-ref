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
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.aaasec.sigserv.xmlsign.registry.MessageDigestAlgorithm;
import com.aaasec.sigserv.xmlsign.registry.SignatureAlgorithm;

import java.util.Objects;
import java.util.Optional;

/**
 * Implementation class for {@link SignatureAlgorithm}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignatureAlgorithmImpl extends AbstractKeyBasedAlgorithm implements SignatureAlgorithm {

  /** Logger. */
  private final static Logger log = LoggerFactory.getLogger(SignatureAlgorithmImpl.class);

  /** For getting the AlgorithmIdentifier. */
  private static SignatureAlgorithmIdentifierFinder algIdFinder =
      new DefaultSignatureAlgorithmIdentifierFinder();

  /** The message digest algorithm. */
  private MessageDigestAlgorithm messageDigestAlgorithm;

  /** The algorithm identifier. */
  private AlgorithmIdentifier algorithmIdentifier;

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
   *          the JOSE algorithm
   * @param messageDigestAlgorithm
   *          the message digest algorithm this signature algorithm uses
   */
  public SignatureAlgorithmImpl(final String uri, final int order, final String keyType,
      final String jcaName, final JWSAlgorithm joseAlgorithm, final MessageDigestAlgorithm messageDigestAlgorithm) {
    super(uri, order, keyType, jcaName, joseAlgorithm);
    this.setMessageDigestAlgorithm(messageDigestAlgorithm);
  }

  /**
   * Protected constructor used by builder.
   *
   * @param uri
   *          the algorithm URI
   */
  protected SignatureAlgorithmImpl(final String uri) {
    super(uri);
  }

  /**
   * Creates a builder.
   *
   * @param uri
   *          the algorithm URI
   * @return the builder
   */
  public static SignatureAlgorithmBuilder builder(final String uri) {
    return new SignatureAlgorithmBuilder(uri);
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
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return this.algorithmIdentifier;
  }

  /** {@inheritDoc} */
  @Override
  protected void setJcaName(final String jcaName) {
    super.setJcaName(jcaName);
    if (this.algorithmIdentifier == null) {
      try {
        this.algorithmIdentifier = algIdFinder.find(jcaName);
      }
      catch (final Exception e) {
      }
      if (this.algorithmIdentifier == null) {
        log.info("No AlgorithmIdentifier exists for {}/{}", this.getUri(), this.getJcaName());
      }
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
    if (!(obj instanceof SignatureAlgorithmImpl)) {
      return false;
    }
    final SignatureAlgorithmImpl other = (SignatureAlgorithmImpl) obj;
    return Objects.equals(this.messageDigestAlgorithm, other.messageDigestAlgorithm);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {

    return String.format("%s, message-digest-algorithm='%s', algorithm-identifier=[%s]",
      super.toString(), Optional.ofNullable(this.messageDigestAlgorithm).map(MessageDigestAlgorithm::getUri).orElse("-"),
      this.algorithmIdentifier != null
          ? (this.algorithmIdentifier.getParameters() == null
              ? this.algorithmIdentifier.getAlgorithm().getId()
              : ASN1Dump.dumpAsString(this.algorithmIdentifier))
          : "-");
  }

  /**
   * Abstract builder for {@link SignatureAlgorithm}.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  public static class SignatureAlgorithmBuilder
      extends AbstractSignatureAlgorithmBuilder<SignatureAlgorithmImpl, SignatureAlgorithmBuilder> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public SignatureAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /** {@inheritDoc} */
    @Override
    protected SignatureAlgorithmBuilder getBuilder() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    protected SignatureAlgorithmImpl createAlgorithm(String algorithmUri) {
      return new SignatureAlgorithmImpl(algorithmUri);
    }

  }

  /**
   * Abstract builder for {@link SignatureAlgorithm}.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  protected static abstract class AbstractSignatureAlgorithmBuilder<T extends SignatureAlgorithmImpl, B extends AbstractSignatureAlgorithmBuilder<T, ? extends AlgorithmBuilder<T>>>
      extends AbstractKeyBasedAlgorithm.AbstractKeyBasedAlgorithmBuilder<T, B> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public AbstractSignatureAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /**
     * Sets the message digest algorithm.
     *
     * @param messageDigestAlgorithm
     *          the digest algorithm
     * @return the builder
     */
    public B messageDigestAlgorithm(final MessageDigestAlgorithm messageDigestAlgorithm) {
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

  }

}
