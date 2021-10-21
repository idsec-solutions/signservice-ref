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
package com.aaasec.sigserv.csdaemon.ca;

import com.aaasec.sigserv.cssigapp.ca.CAFactory;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.x509.V3Extension;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.KeyUsage;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.logging.Logger;

/**
 * Class for generating a Root CA
 */
public class RootCaFactory extends CAFactory {

    private static final Logger LOG = Logger.getLogger(RootCaFactory.class.getName());
    RootCaConfig rootConf;

    public RootCaFactory(RootCaConfig rootConf) {
        this.rootConf = rootConf;
    }

    @Override
    protected void generateRootCertificate() {

        try {
            // Generate root key
            LOG.info("Generating Root RSA key...");
            ca_rsa = generateKeyPair("RSA", rootConf.getKeyLength());
            // Now create the certificates

            Name rootIssuer;
            rootIssuer = new Name();
            rootIssuer.addRDN(ObjectID.country, rootConf.getCountry());
            rootIssuer.addRDN(ObjectID.organization, rootConf.getOrganizationName());
            rootIssuer.addRDN(ObjectID.organizationalUnit, rootConf.getOrgUnitName());
            rootIssuer.addRDN(ObjectID.serialNumber, rootConf.getSerialNumber());
            rootIssuer.addRDN(ObjectID.commonName, rootConf.getCommonName());


            V3Extension[] extensions = new V3Extension[3];
            extensions[0] = new BasicConstraints(true);
            extensions[1] = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature);

            extensions[2] = getAnyCertificatePolicies();

            //
            // create self signed CA cert
            //
            X509Certificate caRoot = null;
            X509Certificate[] chain = new X509Certificate[1];
            // for verifying the created certificates

            LOG.info("create self signed RSA CA certificate...");
            int rootValidYears = rootConf.getValidityYears() < 5 ? 5 : rootConf.getValidityYears();
            GregorianCalendar date = new GregorianCalendar();
            date.add(Calendar.YEAR, -1);
            Date notBefore = date.getTime();
            date.add(Calendar.YEAR, rootValidYears+1);
            Date notAfter = date.getTime();

            caRoot = createRootCertificate(rootIssuer, notBefore,notAfter,ca_rsa.getPublic(),
                    ca_rsa.getPrivate(), AlgorithmID.sha256WithRSAEncryption, extensions);
            // verify the self signed certificate
            caRoot.verify();
            // set the CA cert as trusted root
            chain[0] = caRoot;
            addToKeyStore(ca_rsa, chain, ca.getKsPassword(), ca.getKsAlias());
            //System.out.println(caRoot.toString());
            //rootIssuer.removeRDN(ObjectID.commonName);

        } catch (Exception ex) {
            LOG.warning(ex.getMessage());
        }
    }
}
