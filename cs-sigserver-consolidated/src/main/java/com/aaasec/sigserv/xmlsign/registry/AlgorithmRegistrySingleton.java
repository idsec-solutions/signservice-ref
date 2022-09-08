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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.aaasec.sigserv.xmlsign.registry.Algorithm;
import com.aaasec.sigserv.xmlsign.registry.AlgorithmRegistry;
import com.aaasec.sigserv.xmlsign.registry.impl.StaticAlgorithmRegistry;

import java.util.List;
import java.util.function.Predicate;

/**
 * An singleton for easy access to the {@link AlgorithmRegistry}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AlgorithmRegistrySingleton implements AlgorithmRegistry {

  /** Logger. */
  private final static Logger log = LoggerFactory.getLogger(AlgorithmRegistrySingleton.class);

  /** The singleton instance. */
  private static final AlgorithmRegistrySingleton instance = new AlgorithmRegistrySingleton();

  /** The algorithm registry. */
  private AlgorithmRegistry registry;

  // Hidden constructor.
  private AlgorithmRegistrySingleton() {
  }

  /**
   * Gets the singleton instance.
   *
   * @return the singleton instance
   */
  public static AlgorithmRegistrySingleton getInstance() {
    return instance;
  }

  /**
   * Assigns the {@link AlgorithmRegistry} instance to be used by this singleton. If no instance is assigned, a default
   * implementation of the registry will be used.
   *
   * @param algorithmRegistry
   *          the registry to be used by the singleton
   */
  public static void setAlgorithmRegistry(final AlgorithmRegistry algorithmRegistry) {
    if (instance.registry != null) {
      throw new SecurityException(
        "Cannot assign algorithm registry to AlgorithmRegistrySingleton - it has already been initialized");
    }
    instance.registry = algorithmRegistry;
  }

  /** {@inheritDoc} */
  @Override
  public Algorithm getAlgorithm(final String algorithmUri) {
    return this.getAlgorithmRegistry().getAlgorithm(algorithmUri);
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Algorithm> T getAlgorithm(final String algorithmUri, final Class<T> clazz) {
    return this.getAlgorithmRegistry().getAlgorithm(algorithmUri, clazz);
  }

  /** {@inheritDoc} */
  @Override
  public Algorithm getAlgorithm(final Predicate<Algorithm> predicate) {
    return this.getAlgorithmRegistry().getAlgorithm(predicate);
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Algorithm> T getAlgorithm(final Predicate<Algorithm> predicate, final Class<T> clazz) {
    return this.getAlgorithmRegistry().getAlgorithm(predicate, clazz);
  }

  /** {@inheritDoc} */
  @Override
  public List<Algorithm> getAlgorithms(final Predicate<Algorithm> predicate) {
    return this.getAlgorithmRegistry().getAlgorithms(predicate);
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Algorithm> List<T> getAlgorithms(final Predicate<Algorithm> predicate, final Class<T> clazz) {
    return this.getAlgorithmRegistry().getAlgorithms(predicate, clazz);
  }

  /**
   * Gets the {@link AlgorithmRegistry} instance to use. If no instance has been configured a default implementation is
   * used ({@link StaticAlgorithmRegistry}).
   *
   * @return an AlgorithmRegistry
   */
  private AlgorithmRegistry getAlgorithmRegistry() {
    if (this.registry == null) {
      log.info("Registry not initialized - using default implementation ...");
      synchronized (this) {
        this.registry = new StaticAlgorithmRegistry();
      }
    }
    return registry;
  }

}
