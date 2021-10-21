/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.webapp;

import com.aaasec.sigserv.csdaemon.SignServiceListener;

/**
 *
 * @author stefan
 */
public class CsSigServWebappConstants {

    private CsSigServWebappConstants() {
    }
    
    static {
        SignServiceListener.setServletPath("/cs-sigserver");
    }
}
