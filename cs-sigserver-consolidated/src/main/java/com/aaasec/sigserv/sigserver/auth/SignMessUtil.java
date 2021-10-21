/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigserver.auth;

import com.aaasec.lib.crypto.xml.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.Base64Coder;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageType;

/**
 *
 * @author stefan
 */
public class SignMessUtil {

    public static String getSignMessageB64(SignMessageType signMessage) {
        if (signMessage == null){
            return "";
        }
        byte[] sigMessBytes = XmlBeansUtil.getBytes(signMessage);
        return String.valueOf(Base64Coder.encode(sigMessBytes));
    }    
}
