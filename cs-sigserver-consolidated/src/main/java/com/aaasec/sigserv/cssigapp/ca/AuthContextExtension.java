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
package com.aaasec.sigserv.cssigapp.ca;

import com.aaasec.sigserv.cscommon.marshaller.XmlBeansUtil;
import iaik.asn1.ASN1Object;
import iaik.asn1.ObjectID;
import iaik.asn1.SEQUENCE;
import iaik.asn1.UTF8String;
import iaik.x509.V3Extension;
import iaik.x509.X509ExtensionException;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import org.apache.xmlbeans.XmlException;
import se.elegnamnden.id.authCont.x10.saci.SAMLAuthContextDocument;

/**
 * Auth Context Extension
 */
public class AuthContextExtension extends V3Extension {

    public static final ObjectID extensionOid = new ObjectID("1.2.752.201.5.1", "AuthContextExtension", "Authentication Context Extension");
    public static final String contentType = "http://id.elegnamnden.se/auth-cont/1.0/saci";
    List<SAMLAuthContextDocument> statementInfoList = new ArrayList<SAMLAuthContextDocument>();

    public AuthContextExtension() {
    }

    public AuthContextExtension(List<SAMLAuthContextDocument> statementInfoList) {
        this.statementInfoList = statementInfoList;
    }

    public AuthContextExtension(SAMLAuthContextDocument statementInfo) {
        statementInfoList.clear();
        statementInfoList.add(statementInfo);

    }

    @Override
    public ASN1Object toASN1Object() throws X509ExtensionException {
        SEQUENCE ext = new SEQUENCE();
        for (SAMLAuthContextDocument statementInfo : statementInfoList) {
            try {
                SEQUENCE authCtxt = new SEQUENCE();
                ext.addComponent(authCtxt);
                authCtxt.addComponent(new UTF8String(contentType));
                SAMLAuthContextDocument strippedContextInfo = SAMLAuthContextDocument.Factory.parse(statementInfo.getDomNode(),XmlBeansUtil.stripWhiteSPcae);
                String contextXML = new String(XmlBeansUtil.getBytes(strippedContextInfo, false), Charset.forName("UTF-8"));
                UTF8String statementInfoData = new UTF8String(contextXML);
                authCtxt.addComponent(statementInfoData);
            } catch (XmlException ex) {
                Logger.getLogger(AuthContextExtension.class.getName()).warning(ex.getMessage());
            }
        }
        return ext;
    }

    @Override
    public void init(ASN1Object asno) throws X509ExtensionException {
        statementInfoList.clear();
        try {
            int len = asno.countComponents();
            for (int i = 0; i < len; i++) {
                ASN1Object authCont = asno.getComponentAt(i);
                UTF8String contType = (UTF8String) authCont.getComponentAt(0);
                String type = new String(contType.getByteValue(), Charset.forName("UTF-8"));
                if (!type.equals(contentType)) {
                    continue;
                }
                byte[] statementInfoData = ((UTF8String) authCont.getComponentAt(1)).getByteValue();
                SAMLAuthContextDocument statementInfo = SAMLAuthContextDocument.Factory.parse(new ByteArrayInputStream(statementInfoData));
                statementInfoList.add(statementInfo);
            }
        } catch (Exception ex) {
        }
    }

    @Override
    public int hashCode() {
        return extensionOid.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AuthContextExtension other = (AuthContextExtension) obj;
        if (this.statementInfoList != other.statementInfoList && (this.statementInfoList == null || !this.statementInfoList.equals(other.statementInfoList))) {
            return false;
        }
        return true;
    }

    @Override
    public ObjectID getObjectID() {
        return extensionOid;
    }

    public List<SAMLAuthContextDocument> getStatementInfoList() {
        return statementInfoList;
    }

    /**
     * Returns a string representation of the statement info
     *
     * @return a string representation of the statement info
     */
    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        for (SAMLAuthContextDocument statementInfo : statementInfoList) {
            b.append("SAML Authentication Context Info:\n");
            b.append(new String(XmlBeansUtil.getStyledBytes(statementInfo, false), Charset.forName("UTF-8"))).append("\n");
        }
        return b.toString();
    }
}
