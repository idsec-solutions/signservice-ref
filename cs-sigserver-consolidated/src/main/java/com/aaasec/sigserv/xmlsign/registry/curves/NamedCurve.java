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
package com.aaasec.sigserv.xmlsign.registry.curves;

import java.util.Objects;

/**
 * Representation of a named curve.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NamedCurve {

  /** The name of the curve. */
  private final String name;

  /** The object identifier (in string format). */
  private final String objectIdentifier;

  /** The key length. */
  private final int keyLength;

  /**
   * Constructor.
   *
   * @param name
   *          the name of the curve
   * @param objectIdentifier
   *          the ASN.1 object identifier (in string format)
   * @param keyLength
   *          the length, in bits, of a key using this curve
   */
  public NamedCurve(final String name, final String objectIdentifier, final int keyLength) {
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.objectIdentifier = Objects.requireNonNull(objectIdentifier, "objectIdentifier must not be null");
    this.keyLength = keyLength;
  }

  /**
   * Gets the name of the curve.
   *
   * @return the name
   */
  public String getName() {
    return this.name;
  }

  /**
   * Gets the string representation for the ASN.1 object identifier of the curve.
   *
   * @return the object identifier
   */
  public String getObjectIdentifier() {
    return this.objectIdentifier;
  }

  /**
   * Gets the URI for this curve. This is always "urn:oid:" followed by the object identifier.
   *
   * @return the URI for the curve
   */
  public String getUri() {
    return "urn:oid:" + this.objectIdentifier;
  }

  /**
   * Gets the length, in bits, of a key using this curve.
   *
   * @return key length in bits
   */
  public int getKeyLength() {
    return this.keyLength;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(keyLength, name, objectIdentifier);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof NamedCurve)) {
      return false;
    }
    NamedCurve other = (NamedCurve) obj;
    return keyLength == other.keyLength && Objects.equals(name, other.name) && Objects.equals(objectIdentifier, other.objectIdentifier);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("name='%s', object-identifier='%s', uri='%s', key-length=%d",
      this.name, this.objectIdentifier, this.getUri(), this.keyLength);
  }

}
