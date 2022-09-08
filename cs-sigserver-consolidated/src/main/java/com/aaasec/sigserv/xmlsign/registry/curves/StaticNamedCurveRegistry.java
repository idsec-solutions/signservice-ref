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

import com.aaasec.sigserv.xmlsign.registry.curves.NamedCurve;
import com.aaasec.sigserv.xmlsign.registry.curves.NamedCurveRegistry;
import com.aaasec.sigserv.xmlsign.registry.curves.NamedCurveRegistryImpl;

import java.util.Arrays;

/**
 * Static default implementation of the {@link NamedCurveRegistry}.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class StaticNamedCurveRegistry extends NamedCurveRegistryImpl {

  /** The default curves supported by this registry. */
  public static NamedCurve[] defaultCurves = {
      new NamedCurve("brainpoolP160r1", "1.3.36.3.3.2.8.1.1.1", 160),
      new NamedCurve("brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3", 192),
      new NamedCurve("brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5", 224),
      new NamedCurve("brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7", 256),
      new NamedCurve("brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9", 320),
      new NamedCurve("brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11", 384),
      new NamedCurve("brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13", 512),
      new NamedCurve("secp192r1", "1.2.840.10045.3.1.1", 192),
      new NamedCurve("secp224r1", "1.3.132.0.33", 224),
      new NamedCurve("secp256r1", "1.2.840.10045.3.1.7", 256),
      new NamedCurve("secp384r1", "1.3.132.0.34", 384),
      new NamedCurve("secp521r1", "1.3.132.0.35", 521)
  };

  /**
   * Constructor.
   */
  public StaticNamedCurveRegistry() {
    Arrays.stream(defaultCurves).forEach(c -> this.register(c));
  }

}
