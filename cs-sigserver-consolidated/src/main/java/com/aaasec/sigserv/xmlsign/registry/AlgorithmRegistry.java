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

import com.aaasec.sigserv.xmlsign.registry.Algorithm;
import com.aaasec.sigserv.xmlsign.registry.AlgorithmPredicates;

import java.util.List;
import java.util.function.Predicate;

/**
 * Interface representing an algorithm registry.
 * <p>
 * The interface offers a direct possibility to search for an algorithm based on its URI. To search based on other
 * algorithm properties, use {@link #getAlgorithm(Predicate)} or {@link #getAlgorithms(Predicate)}.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface AlgorithmRegistry {

  /**
   * Gets the algorithm based on its URI.
   *
   * @param algorithmUri
   *          the algorithm URI
   * @return the algorithm, or null if none is found
   */
  Algorithm getAlgorithm(final String algorithmUri);

  /**
   * Gets an algorithm based on its URI and type.
   *
   * @param <T>
   *          the algorithm type
   * @param algorithmUri
   *          the algorithm URI
   * @param clazz
   *          the type representing the algorithm
   * @return the algorithm, or null if none is found
   */
  <T extends Algorithm> T getAlgorithm(final String algorithmUri, final Class<T> clazz);

  /**
   * Gets the first algorithm that matches the supplied predicate.
   * <p>
   * If more than one algorithm matches the supplied predicate, the one with the lowest order is returned.
   * </p>
   *
   * @param predicate
   *          the predicate to apply
   * @return an Algorithm or null if no algorithms in the registry matches
   * @see AlgorithmPredicates
   */
  Algorithm getAlgorithm(final Predicate<Algorithm> predicate);

  /**
   * Gets the first algorithm that matches the given type and supplied predicate.
   * <p>
   * If more than one algorithm matches the supplied predicate, the one with the lowest order is returned.
   * </p>
   *
   * @param predicate
   *          the predicate to apply
   * @param clazz
   *          the type representing the algorithm
   * @return an Algorithm or null if no algorithms in the registry matches
   * @see AlgorithmPredicates
   */
  <T extends Algorithm> T getAlgorithm(final Predicate<Algorithm> predicate, final Class<T> clazz);

  /**
   * Gets all algorithms that matches the supplied predicate.
   * <p>
   * The list is sorted with the lowest algorithms with the lowest order index first.
   * </p>
   *
   * @param predicate
   *          the predicate to apply
   * @return a (possibly empty) list of Algorithm objects
   */
  List<Algorithm> getAlgorithms(final Predicate<Algorithm> predicate);

  /**
   * Gets all algorithms that matches the given type and the supplied predicate.
   * <p>
   * The list is sorted with the lowest algorithms with the lowest order index first.
   * </p>
   *
   * @param predicate
   *          the predicate to apply
   * @param clazz
   *          the type representing the algorithm
   * @return a (possibly empty) list of Algorithm objects
   */
  <T extends Algorithm> List<T> getAlgorithms(final Predicate<Algorithm> predicate, final Class<T> clazz);

}
