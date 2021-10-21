/*
 * Copyright 2013 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *   Licensed under the EUPL, Version 1.1 or ñ as soon they will be approved by the 
 *   European Commission - subsequent versions of the EUPL (the "Licence");
 *   You may not use this work except in compliance with the Licence. 
 *   You may obtain a copy of the Licence at:
 * 
 *   http://joinup.ec.europa.eu/software/page/eupl 
 * 
 *   Unless required by applicable law or agreed to in writing, software distributed 
 *   under the Licence is distributed on an "AS IS" basis,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
 *   implied.
 *   See the Licence for the specific language governing permissions and limitations 
 *   under the Licence.
 */
package com.aaasec.sigserv.cscommon;

import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * URL Encoder
 */
public class URLEncoder {

    public static String queryEncode(String codedStr) {
        // Add any custom pre processing here

        String coded = "";
        try {
            coded = java.net.URLEncoder.encode(codedStr, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(URLEncoder.class.getName()).log(Level.WARNING, null, ex);
        }

        //Add any custom cleanup or customization if needed here

        return coded;
    }
    
    public static String maskB64String (String b64String){
        return b64String.replace('+', '-');
    }
    
    public static String unmaskB64String (String masked){
        return masked.replace('-', '+');
    }
    
}
