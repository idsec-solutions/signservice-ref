/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigserver.auth;

import java.util.List;

/**
 *
 * @author stefan
 */
public enum LevelOfAssucance {

    loa1("http://id.elegnamnden.se/loa/1.0/loa1", null),
    loa2("http://id.elegnamnden.se/loa/1.0/loa2", "http://id.elegnamnden.se/loa/1.0/loa2-sigmessage"),
    loa3("http://id.elegnamnden.se/loa/1.0/loa3", "http://id.elegnamnden.se/loa/1.0/loa3-sigmessage"),
    loa4("http://id.elegnamnden.se/loa/1.0/loa4", "http://id.elegnamnden.se/loa/1.0/loa4-sigmessage"),
    eidasLow("http://id.elegnamnden.se/loa/1.0/eidas-low","http://id.elegnamnden.se/loa/1.0/eidas-low-sigm"),
    eidasSub("http://id.elegnamnden.se/loa/1.0/eidas-sub","http://id.elegnamnden.se/loa/1.0/eidas-sub-sigm"),
    eidasSubNF("http://id.elegnamnden.se/loa/1.0/eidas-nf-sub","http://id.elegnamnden.se/loa/1.0/eidas-nf-sub-sigm"),
    eidasHigh("http://id.elegnamnden.se/loa/1.0/eidas-high","http://id.elegnamnden.se/loa/1.0/eidas-high-sigm"),
    eidasHighNF("http://id.elegnamnden.se/loa/1.0/eidas-nf-high","http://id.elegnamnden.se/loa/1.0/eidas-nf-high-sigm"),
    uncertifiedLoa3("http://id.swedenconnect.se/loa/1.0/uncertified-loa3","http://id.swedenconnect.se/loa/1.0/uncertified-loa3-sigmessage"),
    ;

    String contextClassRef;
    String sigMessContextClassRef;

    private LevelOfAssucance(String contextClassRef, String sigMessContextClassRef) {
        this.contextClassRef = contextClassRef;
        this.sigMessContextClassRef = sigMessContextClassRef;
    }

    public String getContextClassRef() {
        return contextClassRef;
    }

    public String getSigMessContextClassRef() {
        return sigMessContextClassRef;
    }

    public static String getRequestContextClassRef(String requestedLoa, boolean isSignMessage, boolean mustDisplay, List<String> idpSupportedLoa, LevelOfAssucance defaultLoa) {
        LevelOfAssucance reqLoa = getRequestedLoA(requestedLoa, defaultLoa);

        if (!isSignMessage) {
            if (isAuthContextSupportedByIdP(reqLoa, idpSupportedLoa, false)) {
                return reqLoa.getContextClassRef();
            }
            return null;
        }

        // Sign message is provided in request
        if (isAuthContextSupportedByIdP(reqLoa, idpSupportedLoa, true)) {
            return reqLoa.getSigMessContextClassRef();
        }
        if (mustDisplay) {
            // Error. Signmessage is not supported by IdP bur display is required
            return null;
        }

        //Signmessage is not supported by IdP, but not required either. Send normal request if supported by IdP.
        if (isAuthContextSupportedByIdP(reqLoa, idpSupportedLoa, false)) {
            return reqLoa.getContextClassRef();
        }
        return null;
    }

    public static LevelOfAssucance getRequestedLoA(String requestedContextClassRef, LevelOfAssucance defaultLoa) {
        if (requestedContextClassRef != null) {
            for (LevelOfAssucance loa : values()) {
                String cc = loa.getContextClassRef();
                String smcc = loa.getSigMessContextClassRef();

                if (smcc != null && requestedContextClassRef.equalsIgnoreCase(smcc)) {
                    return loa;
                }

                if (requestedContextClassRef.equalsIgnoreCase(cc)) {
                    return loa;
                }
            }
        }
        return defaultLoa;
    }

    private static boolean isAuthContextSupportedByIdP(LevelOfAssucance reqLoa, List<String> idpSupportedLoa, boolean signMessage) {
        String requiredClassRef = reqLoa.getContextClassRef();
        if (signMessage) {
            requiredClassRef = reqLoa.getSigMessContextClassRef();
        }
        return idpSupportedLoa.contains(requiredClassRef.toLowerCase());
    }

}
