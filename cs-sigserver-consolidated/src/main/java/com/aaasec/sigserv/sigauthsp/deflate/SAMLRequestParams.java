/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.deflate;

import com.aaasec.lib.utils.URIComponentCoder;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.xmlbeans.XmlObject;

/**
 *
 * @author stefan
 */
public class SAMLRequestParams {

    private String relayState;
    private XmlObject samlRequest;

    public SAMLRequestParams(String path) throws MalformedURLException {
        this(new URL("https://example.com" + path));
    }

    public SAMLRequestParams(URL requestUrl) {
        String query = requestUrl.getQuery();
        String[] qParam = query.split("&");
        relayState = getParamVal(qParam, "RelayState");
        String encRequest = getParamVal(qParam, "SAMLRequest");
        try {
            InputStream decodeMessage = SAMLMessageDecoder.decodeMessage(encRequest);
            samlRequest = XmlObject.Factory.parse(decodeMessage);
        } catch (Exception ex) {
            Logger.getLogger(SAMLRequestParams.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private String getParamVal(String[] qParam, String paramName) {
        for (String paramData : qParam) {
            String[] paramFrag = paramData.split("=");
            try {
                if (paramFrag[0].equalsIgnoreCase(paramName)) {
                    return URIComponentCoder.decodeURIComponent(paramFrag[1]);
                }
            } catch (Exception ex) {
            }
        }
        return null;
    }

    public String getRelayState() {
        return relayState;
    }

    public XmlObject getSamlRequest() {
        return samlRequest;
    }
}
