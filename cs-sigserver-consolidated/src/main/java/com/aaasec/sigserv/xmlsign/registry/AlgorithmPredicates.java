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
package com.aaasec.sigserv.xmlsign.registry;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.aaasec.sigserv.xmlsign.registry.Algorithm;
import com.aaasec.sigserv.xmlsign.registry.AlgorithmIdentifierAware;
import com.aaasec.sigserv.xmlsign.registry.AlgorithmRegistry;
import com.aaasec.sigserv.xmlsign.registry.AlgorithmType;
import com.aaasec.sigserv.xmlsign.registry.KeyBasedAlgorithm;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * A set of "ready-to-go" predicates to use when searching for algorithms in the {@link AlgorithmRegistry}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AlgorithmPredicates {

  /**
   * A predicate that can be combined with other predicates to ensure that the resulting {@link com.aaasec.sigserv.xmlsign.registry.Algorithm} is not
   * blacklisted.
   *
   * @return a predicate
   */
  public static Predicate<com.aaasec.sigserv.xmlsign.registry.Algorithm> notBlacklisted() {
    return (a) -> !a.isBlacklisted();
  }

  /**
   * Predicate for finding an algorithm based on its JCA name.
   *
   * @param the
   *          JCA name
   * @return a predicate
   */
  public static Predicate<Algorithm> fromJcaName(final String jcaName) {
    return (a) -> Objects.equals(a.getJcaName(), jcaName);
  }

  /**
   * Predicate for finding an algorithm based on its type.
   *
   * @param type
   *          the algorithm type
   * @return a predicate
   */
  public static Predicate<Algorithm> fromType(final AlgorithmType type) {
    return (a) -> a.getType().equals(type);
  }

  /**
   * Predicate for finding an algorithm based on its key type.
   *
   * @param keyType
   *          the key type
   * @return a predicate
   */
  public static Predicate<Algorithm> fromKeyType(final String keyType) {
    return (a) -> KeyBasedAlgorithm.class.isInstance(a)
        && Objects.equals(KeyBasedAlgorithm.class.cast(a).getKeyType(), keyType);
  }

  /**
   * Predicate for finding an algorithm based on its {@code AlgorithmIdentifier}.
   *
   * @param algorithmIdentifier
   *          the algorithm identifier
   * @return a predicate
   */
  public static Predicate<Algorithm> fromAlgorithmIdentifier(final AlgorithmIdentifier algorithmIdentifier) {
    return (a) -> AlgorithmIdentifierAware.class.isInstance(a)
        && Objects.equals(AlgorithmIdentifierAware.class.cast(a).getAlgorithmIdentifier(), algorithmIdentifier);
  }

  /**
   * Predicate for finding an algorithm based on its {@code AlgorithmIdentifier}. The method implementation is "relaxed"
   * which means that if no parameters are supplied in the {@code algorithmIdentifier} the comparison of parameters will
   * be excluded. This covers for the case when the special NULL param is used.
   * <p>
   * Also, for RSA-PSS, we compare only the digest part of the parameters.
   * </p>
   *
   * @param algorithmIdentifier
   *          the algorithm identifier
   * @return a predicate
   */
  public static Predicate<Algorithm> fromAlgorithmIdentifierRelaxed(final AlgorithmIdentifier algorithmIdentifier) {
    return (algorithm) -> {
      if (!AlgorithmIdentifierAware.class.isInstance(algorithm)) {
        return false;
      }
      final AlgorithmIdentifier ai = AlgorithmIdentifierAware.class.cast(algorithm).getAlgorithmIdentifier();
      if (ai == null) {
        return false;
      }
      if (algorithmIdentifier.getParameters() == null) {
        return Objects.equals(algorithmIdentifier.getAlgorithm(), ai.getAlgorithm());
      }
      if (algorithmIdentifier.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS)) {
        if (!ai.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS)) {
          return false;
        }
        // Compare the hash algorithms ...
        return Objects.equals(
          Optional.ofNullable(algorithmIdentifier.getParameters()).map(p -> RSASSAPSSparams.getInstance(p))
            .map(RSASSAPSSparams::getHashAlgorithm).map(AlgorithmIdentifier::getAlgorithm).orElse(null),
          Optional.ofNullable(ai.getParameters()).map(p -> RSASSAPSSparams.getInstance(p))
            .map(RSASSAPSSparams::getHashAlgorithm).map(AlgorithmIdentifier::getAlgorithm).orElse(null));
      }
      return algorithmIdentifier.equals(AlgorithmIdentifierAware.class.cast(algorithm).getAlgorithmIdentifier());
    };
  }

  // Hidden constructor
  private AlgorithmPredicates() {
  }

}
