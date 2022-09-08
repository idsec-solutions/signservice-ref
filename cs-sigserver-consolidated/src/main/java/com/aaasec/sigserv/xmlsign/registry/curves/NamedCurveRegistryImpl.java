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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.aaasec.sigserv.xmlsign.registry.curves.NamedCurve;
import com.aaasec.sigserv.xmlsign.registry.curves.NamedCurveRegistry;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Implementation of the {@link NamedCurveRegistry} interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NamedCurveRegistryImpl implements NamedCurveRegistry {

  /** Logger. */
  private final static Logger log = LoggerFactory.getLogger(NamedCurveRegistryImpl.class);

  /** The registry. */
  private final Map<String, NamedCurve> registry;

  /**
   * Default constructor.
   */
  public NamedCurveRegistryImpl() {
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
  public NamedCurveRegistryImpl(final List<NamedCurve> registry) {
    this();
    if (registry != null) {
      registry.forEach(c -> this.register(c));
    }
  }

  /**
   * Registers the given curve in the registry.
   *
   * @param curve
   *          the curve to register
   */
  public void register(final NamedCurve curve) {
    log.debug("Registering curve: {}", curve);
    this.registry.put(curve.getName(), curve);
  }

  /**
   * Removes the given curve from the registry.
   *
   * @param name
   *          the curve name
   */
  public void unregister(final String name) {
    final NamedCurve curve = this.registry.remove(name);
    if (curve != null) {
      log.debug("Algorithm '{}' was removed from the registry", name);
    }
  }

  /** {@inheritDoc} */
  @Override
  public NamedCurve getCurve(final String name) {
    return this.registry.get(name);
  }

  /** {@inheritDoc} */
  @Override
  public NamedCurve getCurve(final Predicate<NamedCurve> predicate) {
    return this.registry.values().stream()
        .filter(predicate)
        .findFirst()
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public List<NamedCurve> getCurves(final Predicate<NamedCurve> predicate) {
    return this.registry.values().stream()
        .filter(predicate)
        .collect(Collectors.toList());
  }

}
