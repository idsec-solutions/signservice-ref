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
package com.aaasec.sigserv.sigauthsp.utils;

import com.aaasec.lib.crypto.xml.XMLSign;


/**
 * Signature Algorithms.
 */
public enum SigAlgorithms {

    RSA(XMLSign.SHA256, XMLSign.RSA_SHA256, "SHA-256", "SHA1withRSA"), ECDSA(XMLSign.SHA256, XMLSign.ECDSA_SHA256, "SHA-256", "SHA1withECDSA");
    private static int[] sha256Prefix = new int[]{0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    private String digestAlgo;
    private String sigAlgo;
    private String messageDigestName;
    private String dummyCertAlgo;

    private SigAlgorithms(String digestAlgo, String sigAlgo, String messageDigestName, String dummyCertAlgo) {
        this.digestAlgo = digestAlgo;
        this.sigAlgo = sigAlgo;
        this.messageDigestName = messageDigestName;
        this.dummyCertAlgo = dummyCertAlgo;
    }

    public String getDigestAlgo() {
        return digestAlgo;
    }

    public String getSigAlgo() {
        return sigAlgo;
    }

    public String getDummyCertAlgo() {
        return dummyCertAlgo;
    }

    public String getMessageDigestName() {
        return messageDigestName;
    }

    public static SigAlgorithms getAlgoByURI(String algoURI) {
        if (algoURI.equalsIgnoreCase(XMLSign.ECDSA_SHA256)) {
            return SigAlgorithms.ECDSA;
        }
        if (algoURI.equalsIgnoreCase(XMLSign.RSA_SHA256)) {
            return SigAlgorithms.RSA;
        }
        return SigAlgorithms.RSA;
    }

    public byte[] getPKCS1hash(byte[] hash) {
        byte[] p1Hash;
        if (messageDigestName.equalsIgnoreCase("SHA-256")) {
            int len = hash.length + sha256Prefix.length;
            p1Hash = new byte[len];
            for (int i = 0; i < sha256Prefix.length; i++) {
                p1Hash[i] = (byte) sha256Prefix[i];
            }
            System.arraycopy(hash, 0, p1Hash, sha256Prefix.length, hash.length);
            return p1Hash;
        }
        // add support for other hash algorithms

        return null;
    }
}
