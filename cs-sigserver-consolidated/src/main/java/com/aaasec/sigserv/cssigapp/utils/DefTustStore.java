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
package com.aaasec.sigserv.cssigapp.utils;

import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.FileOps;
import iaik.x509.X509Certificate;
import java.io.File;
import java.util.List;

/**
 * Default trust store.
 */
public class DefTustStore implements Constants {

    private static final String[] defTrustedCerts = new String[]{
        "-----BEGIN CERTIFICATE-----",
        "MIICwzCCAasCBgE1sYAgVjANBgkqhkiG9w0BAQUFADAlMSMwIQYDVQQDDBpodHRwczovL2VpZDIu",
        "a29ua2kuc2UvY3NzcDAeFw0xMjAyMjQyMjM0MDhaFw0xMjAyMjQyMjM0MjhaMCUxIzAhBgNVBAMM",
        "Gmh0dHBzOi8vZWlkMi5rb25raS5zZS9jc3NwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC",
        "AQEAkDvxXr+tNI2lLElIvEKNRv3SwmavkwU4PXDcuaC0VoyZsnJ4mYXhonpEhjLcDjOMehCbgM5B",
        "Caq/pp1Hv5DTwmPZnrcaNzT0sJx9iijdUso9eaS8cBIleadPQaGXjGQlw3iyfbPgACR1ItZtQeyJ",
        "tyGJLHRQoYTaTbskHGFy7DJKkFejHEsAShdA4DkEUhh3UmQidZWJCdLgv6SocOr9k6NdU65Qd1H6",
        "NlMZUQ7E6rbWwhf7DsiK7c5Jrl0LJpL1NJNIGXVVVtQ7AbuUoJLuLbRYz+JynT0eUYS0CUWbWBTa",
        "SDPvC8xP5s+JQvgQBhE5Jnr7ccMHw++pYepos9cqswIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBn",
        "guwA018y+BAoebJQdbpWX9x3SD91B9nPnNlXXGCV5aYZ8/J6WAEaJBK2vreimVP22OThKH+qNNs7",
        "X5KLLkF7Vl6yhvBTpOTgH5pgqPhymLUPhN7xPHuYalSIqP7APobxCgffDEjTkXXZuqyu5ImNIQkM",
        "/e1xkz99gdLyzwphxgzFQX1CC08XNSoNXr7Xm/hyRXNAg6MugHqOHaBGk3/XIIKovAw/Kafupuo9",
        "K3ovhNXLWJiP3/ubB1oEF91h3SuydVRYwuzmr4UR05dsgvgbRa7zMKkLmbvPsU6VoYDxV/SoAR7k",
        "eKGNNaKejEANS+X/D6Z+jDc9cYExttjKJ5Z5",
        "-----END CERTIFICATE-----"};
    static String pemCert;

    static {
        StringBuilder b = new StringBuilder();
        for (String crtLine : defTrustedCerts) {
            b.append(crtLine).append(LF);
        }
        pemCert = b.toString();
    }

    ;

    public static List<X509Certificate> getCertificates(File certFile) {
        List<X509Certificate> cert = null;

        if (certFile.canRead()) {
            String pemCerts = FileOps.readTextFile(certFile);
            cert = GeneralStaticUtils.getCertsFromPemList(pemCerts);
        }

        if (cert == null) {
            if (!certFile.canRead()) {
                certFile.getParentFile().mkdirs();
            }
            FileOps.saveTxtFile(certFile, pemCert);
            cert = GeneralStaticUtils.getCertsFromPemList(pemCert);
        }
        return cert;
    }
}
