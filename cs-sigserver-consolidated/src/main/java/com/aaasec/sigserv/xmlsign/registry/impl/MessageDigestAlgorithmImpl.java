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

import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.aaasec.sigserv.xmlsign.registry.MessageDigestAlgorithm;

/**
 * Implementation class for the {@link MessageDigestAlgorithm}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class MessageDigestAlgorithmImpl extends com.aaasec.sigserv.xmlsign.registry.impl.AbstractAlgorithm implements MessageDigestAlgorithm {

  /** Logger. */
  private final static Logger log = LoggerFactory.getLogger(MessageDigestAlgorithmImpl.class);

  /** For getting the AlgorithmIdentifier. */
  private static DigestAlgorithmIdentifierFinder algIdFinder =
      new DefaultDigestAlgorithmIdentifierFinder();

  /** The algorithm identifier. */
  private AlgorithmIdentifier algorithmIdentifier;

  /**
   * Constructor.
   *
   * @param uri
   *          the algorithm URI
   * @param order
   *          the ordering for the algorithm
   * @param jcaName
   *          the JCA name
   */
  public MessageDigestAlgorithmImpl(final String uri, final int order, final String jcaName) {
    super(uri, order, jcaName);
  }

  /**
   * Protected constructor used by builder.
   *
   * @param uri
   *          the algorithm URI
   */
  protected MessageDigestAlgorithmImpl(final String uri) {
    super(uri);
  }

  /**
   * Creates a builder.
   *
   * @param uri
   *          the algorithm URI
   * @return the builder
   */
  public static MessageDigestAlgorithmBuilder builder(final String uri) {
    return new MessageDigestAlgorithmBuilder(uri);
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
  public String toString() {
    return String.format("%s, algorithm-identifier=[%s]", super.toString(),
      this.algorithmIdentifier != null
          ? (this.algorithmIdentifier.getParameters() == null
              ? this.algorithmIdentifier.getAlgorithm().getId()
              : ASN1Dump.dumpAsString(this.algorithmIdentifier))
          : "-");
  }

  /**
   * Builder for {@link MessageDigestAlgorithm}.
   *
   * @author Martin Lindström (martin@idsec.se)
   * @author Stefan Santesson (stefan@idsec.se)
   */
  public static class MessageDigestAlgorithmBuilder
      extends AbstractAlgorithmBuilder<MessageDigestAlgorithmImpl, MessageDigestAlgorithmBuilder> {

    /**
     * Constructor.
     *
     * @param algorithmUri
     *          the algorithm URI
     */
    public MessageDigestAlgorithmBuilder(final String algorithmUri) {
      super(algorithmUri);
    }

    /** {@inheritDoc} */
    @Override
    protected MessageDigestAlgorithmBuilder getBuilder() {
      return this;
    }

    /** {@inheritDoc} */
    @Override
    protected MessageDigestAlgorithmImpl createAlgorithm(final String algorithmUri) {
      return new MessageDigestAlgorithmImpl(algorithmUri);
    }

  }

}
