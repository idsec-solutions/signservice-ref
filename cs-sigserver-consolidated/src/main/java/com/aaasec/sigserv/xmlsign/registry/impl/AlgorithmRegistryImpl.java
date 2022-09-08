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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.aaasec.sigserv.xmlsign.registry.Algorithm;
import com.aaasec.sigserv.xmlsign.registry.AlgorithmRegistry;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Default implementation of the {@link AlgorithmRegistry} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AlgorithmRegistryImpl implements AlgorithmRegistry {

  /** Logger. */
  private final static Logger log = LoggerFactory.getLogger(AlgorithmRegistryImpl.class);

  /** The registry. */
  private final Map<String, Algorithm> registry;

  /**
   * Default constructor.
   */
  public AlgorithmRegistryImpl() {
    this.registry = new ConcurrentHashMap<>();
  }

  /**
   * Constructor setting up the registry according to the supplied list.
   * <p>
   * Note: a copy of the supplied registry is made.
   * </p>
   *
   * @param registry
   *          initial contents of the registry
   */
  public AlgorithmRegistryImpl(final List<Algorithm> registry) {
    this();
    if (registry != null) {
      registry.forEach(a -> this.register(a));
    }
  }

  /**
   * Registers the given algorithm in the registry.
   *
   * @param algorithm
   *          the algorithm to register
   */
  public void register(final Algorithm algorithm) {
    log.debug("Registering algorithm: {}", algorithm);
    if (algorithm.getUri() == null) {
      throw new IllegalArgumentException("Invalid algorithm - missing URI");
    }
    this.registry.put(algorithm.getUri(), algorithm);
  }

  /**
   * Removes the given algorithm from the registry.
   *
   * @param algorithmUri
   *          the algorithm URI
   */
  public void unregister(final String algorithmUri) {
    final Algorithm alg = this.registry.remove(algorithmUri);
    if (alg != null) {
      log.debug("Algorithm '{}' was removed from the registry", algorithmUri);
    }
  }

  /** {@inheritDoc} */
  @Override
  public Algorithm getAlgorithm(final String algorithmUri) {
    return this.registry.get(algorithmUri);
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Algorithm> T getAlgorithm(final String algorithmUri, final Class<T> clazz) {
    try {
      return clazz.cast(this.getAlgorithm(algorithmUri));
    }
    catch (final ClassCastException e) {
      log.info("The algorithm '{}' is not of type '{}'", algorithmUri, clazz.getSimpleName());
      return null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Algorithm> T getAlgorithm(final Predicate<Algorithm> predicate, final Class<T> clazz) {
    return this.registry.values().stream()
      .filter(a -> clazz.isInstance(a))
      .map(a -> clazz.cast(a))
      .filter(predicate)
      .min(Comparator.comparing(Algorithm::getOrder))
      .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public Algorithm getAlgorithm(final Predicate<Algorithm> predicate) {
    return this.registry.values().stream()
      .filter(predicate)
      .min(Comparator.comparing(Algorithm::getOrder))
      .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public List<Algorithm> getAlgorithms(final Predicate<Algorithm> predicate) {
    return this.registry.values().stream()
      .filter(predicate)
      .sorted((a1, a2) -> Integer.compare(a1.getOrder(), a2.getOrder()))
      .collect(Collectors.toList());
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Algorithm> List<T> getAlgorithms(final Predicate<Algorithm> predicate, final Class<T> clazz) {
    return this.registry.values().stream()
      .filter(a -> clazz.isInstance(a))
      .map(a -> clazz.cast(a))
      .filter(predicate)
      .sorted((a1, a2) -> Integer.compare(a1.getOrder(), a2.getOrder()))
      .collect(Collectors.toList());
  }

}
