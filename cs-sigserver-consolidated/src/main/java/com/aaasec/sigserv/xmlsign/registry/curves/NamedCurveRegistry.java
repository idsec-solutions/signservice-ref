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

import java.util.List;
import java.util.function.Predicate;

/**
 * A registry for named curves.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface NamedCurveRegistry {

  /**
   * Gets a {@link NamedCurve} based on its name.
   *
   * @param name
   *          the name
   * @return the NamedCurve or null if no match is found
   */
  NamedCurve getCurve(final String name);

  /**
   * Gets a {@link NamedCurve} based on the given predicate.
   *
   * @param predicate
   *          the predicate
   * @return the first curve that matches the supplied predicate, or null if no matches are found
   */
  NamedCurve getCurve(final Predicate<NamedCurve> predicate);

  /**
   * Gets all curves that matches the given predicate.
   *
   * @param predicate
   *          the predicate
   * @return a (possibly empty) list of NamedCurve objects
   */
  List<NamedCurve> getCurves(final Predicate<NamedCurve> predicate);

}
