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
package com.aaasec.sigserv.cssigapp.data;

import java.math.BigInteger;

/**
 * Database model for the CA Log
 */
public class DbCALog {

    private int logCode;
    private String eventString;
    private String logParameter;
    private long logTime;
    
    
    public DbCALog (){        
    }

    public String getEventString() {
        return eventString;
    }

    public void setEventString(String eventString) {
        this.eventString = eventString;
    }

    public int getLogCode() {
        return logCode;
    }

    public void setLogCode(int logCode) {
        this.logCode = logCode;
    }

    public String getLogParameter() {
        return logParameter;
    }

    public void setLogParameter(String logParameter) {
        this.logParameter = logParameter;
    }

    public long getLogTime() {
        return logTime;
    }

    public void setLogTime(long logTime) {
        this.logTime = logTime;
    }
    
    public static class Parameters{
        public int reason=-1;
        public BigInteger serial = BigInteger.ZERO;

        public Parameters() {
        }
        
    }       
}