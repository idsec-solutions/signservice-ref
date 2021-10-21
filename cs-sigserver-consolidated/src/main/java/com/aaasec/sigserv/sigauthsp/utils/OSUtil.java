/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.utils;

import com.aaasec.lib.crypto.xml.XMLSign;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;

import com.aaasec.lib.crypto.xml.XmlUtils;
import com.aaasec.sigserv.sigauthsp.deflate.SAMLRequestParams;
import com.aaasec.sigserv.sigauthsp.deflate.XmlBeansUtil;
import com.aaasec.sigserv.sigauthsp.enums.MessageMimeType;
import com.aaasec.sigserv.sigauthsp.models.KeyStoreBundle;
import org.apache.xmlbeans.XmlObject;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.xml.sax.SAXException;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageDocument;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageType;
import com.aaasec.sigserv.sigauthsp.models.AuthReqData;
import com.aaasec.sigserv.sigauthsp.opensaml.AbstractOpenSamlObj;
import com.aaasec.sigserv.sigauthsp.opensaml.ApIssuer;
import com.aaasec.sigserv.sigauthsp.opensaml.ApNameIdPolicy;
import com.aaasec.sigserv.sigauthsp.opensaml.ApReqAuthContextClass;
import com.aaasec.sigserv.sigauthsp.opensaml.ApRequest;
import com.aaasec.sigserv.sigauthsp.opensaml.Builder;

/**
 * @author stefan
 */
public class OSUtil {

    private static final Logger LOG = Logger.getLogger(OSUtil.class.getName());
    public static final String postBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public static final String redirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    public static final SAMLVersion version = SAMLVersion.VERSION_20;
    public static final boolean isPassive = false;
    public static final String authContextClassRef = "http://id.elegnamnden.se/loa/1.0/loa3";
    private static final Random rng = new Random(System.currentTimeMillis());

    private OSUtil() {
    }

    public static ApRequest getRequest(AuthReqData ard, String requestProtocolBinding) {
        ApRequest request = new ApRequest();
        request.obj.setDestination(ard.getReqUrl());
        request.obj.setForceAuthn(ard.isForceAuthn());
        if (ard.getId() == null) {
            request.obj.setID("_" + new BigInteger(128, rng).toString(16));
        } else {
            request.obj.setID("_" + ard.getId());
        }
        request.obj.setIsPassive(isPassive);
        long currentMs = System.currentTimeMillis() - 3000;
        request.obj.setIssueInstant(new DateTime(currentMs));
        request.obj.setProtocolBinding(postBinding);
        request.obj.setVersion(version);

        ApIssuer issuer = new ApIssuer();
        issuer.obj.setValue(ard.getSpEntityId());
        request.obj.setIssuer(issuer.obj);

        ApNameIdPolicy nidPolicy = new ApNameIdPolicy();
        nidPolicy.obj.setAllowCreate(!ard.isPersistentId());
        request.obj.setNameIDPolicy(nidPolicy.obj);

        if (ard.getLoa() != null && !ard.getLoa().get(0).equalsIgnoreCase("none")) {
            ApReqAuthContextClass reqAcc = new ApReqAuthContextClass();
            reqAcc.obj.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
            reqAcc.setAuthContextClassRef(ard.getLoa());
            request.obj.setRequestedAuthnContext(reqAcc.obj);
        }

        if (ard.getSignMessage() != null || ard.getSadRequest() != null || ard.getPrincipalSelection() != null) {
            try {
                request.obj.setExtensions(buildRequestExtensions(ard));
            } catch (CertificateEncodingException | KeyStoreException | DecryptionException | UnrecoverableKeyException | IOException | SAXException | ParserConfigurationException ex) {
                Logger.getLogger(OSUtil.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        return request;
    }

    public static void signRequest(ApRequest request, KeyStoreBundle spKeyStore) throws SecurityException, SignatureException, MarshallingException, CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        SignSamlUtil.sign(request.obj, new ApCredential(spKeyStore));
    }

    public static String getRequestXhtmlForm(ApRequest request, String idpEntityId, String reqUrl) {
        try {
            byte[] reqBytes = XmlBeansUtil.getCanonicalBytes(XmlObject.Factory.parse(request.getXmlDoc()));
            String id = request.obj.getID();
            String reqXhtmlForm = SamlXhtmlForm.getSignXhtmlForm(SamlXhtmlForm.Type.AUTHN_REQUEST_FORM, reqUrl, reqBytes, id);
            return reqXhtmlForm;
        } catch (Exception ex) {
            return null;
        }
    }

    public String getXMLString(AbstractOpenSamlObj osObj) {
        return XMLHelper.prettyPrintXML(osObj.getElement());
    }

    public static String getAuthnRequestUrl(ApRequest aPauthRequest, String idpEntityId, String reqUrl) {
        try {
            String samlResquest = getDeflatedSamlRequest(aPauthRequest);
            String urlReq = getUrlRequest(reqUrl, "SAMLRequest=" + URLEncoder.encode(samlResquest, "UTF-8") + "&RelayState=" + aPauthRequest.obj.getID());
            return urlReq;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String getSignedAuthnRequestUrl(ApRequest aPauthRequest, String idpEntityId, String reqUrl, KeyStoreBundle ksBundle) {
        try {
            String samlResquest = getDeflatedSamlRequest(aPauthRequest);
            String tbsString = "SAMLRequest=" + URLEncoder.encode(samlResquest, "UTF-8")
                    + "&RelayState=" + aPauthRequest.obj.getID()
                    + "&SigAlg=" + URLEncoder.encode(XMLSign.RSA_SHA256, "UTF-8");

            byte[] tbsBytes = tbsString.getBytes(Charset.forName("UTF-8"));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(tbsBytes);
            byte[] tbsDigest = SigAlgorithms.RSA.getPKCS1hash(digest);
            byte[] rsaSign = XMLSign.rsaSign(tbsDigest, ksBundle.getPrivate());
            String encodedSig = URLEncoder.encode(Base64.encodeBytes(rsaSign), "UTF-8");
            String urlReq = getUrlRequest(reqUrl, tbsString + "&Signature=" + encodedSig);
            return urlReq;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String getDeflatedSamlRequest(ApRequest aPauthRequest) throws IOException {
        org.w3c.dom.Element authDOM = aPauthRequest.getElement();
        StringWriter rspWrt = new StringWriter();
        XMLHelper.writeNode(authDOM, rspWrt);
        String messageXML = rspWrt.toString();

        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater)) {
            deflaterOutputStream.write(messageXML.getBytes());
        }

        String samlResquest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
        return samlResquest;
    }

    private static String getUrlRequest(String destinationUrl, String queryParams) throws IllegalArgumentException {
        if (destinationUrl==null){
            throw new IllegalArgumentException("Null request URL provided");
        }
        try {
            URL url = new URL(destinationUrl);
            String query = url.getQuery();
            if (query==null){
                return destinationUrl + "?" + queryParams;
            }
            return destinationUrl + "&" + queryParams;

        } catch (Exception ex) {
            throw new IllegalArgumentException("Illegal url parameter (" + destinationUrl+")");
        }
    }

    public static String inflate(String source) {
        try {
            SAMLRequestParams srp = new SAMLRequestParams(source);
            String prettyPrint = new String(XmlBeansUtil.getStyledBytes(srp.getSamlRequest()), Charset.forName("UTF-8"));
            return prettyPrint;

        } catch (Exception ex) {
            StringBuilder b = new StringBuilder();
            b.append("Failed to decode input value:\n");
            b.append("Exception: ").append(ex.getClass().getName()).append("\n");
            b.append("Message: ").append(ex.getMessage()).append("\n");
            System.out.println(b.toString());
            return null;
        }
    }

    private static Extensions buildRequestExtensions(AuthReqData ard)
            throws CertificateEncodingException, KeyStoreException, DecryptionException, UnrecoverableKeyException, IOException, SAXException, ParserConfigurationException {
        QName extQname = new QName("urn:oasis:names:tc:SAML:2.0:protocol", "Extensions", "saml2p");
        Extensions extensions = (Extensions) Builder.builderFactory.getBuilder(extQname).buildObject(extQname);

        if (ard.getSignMessage() != null) {
            XSAny signMessageElm = new XSAnyBuilder().buildObject("http://id.elegnamnden.se/csig/1.1/dss-ext/ns", "SignMessage", "eid2");

            signMessageElm.setDOM(XmlUtils.getDocument(XmlBeansUtil.getBytes(ard.getSignMessage())).getDocumentElement());
            extensions.getUnknownXMLObjects().add(signMessageElm);
        }

        if (ard.getSadRequest() != null) {
            XSAny sadReqElm = new XSAnyBuilder().buildObject("http://id.elegnamnden.se/csig/1.1/sap/ns", "SADRequest", "sap");

            sadReqElm.setDOM(XmlUtils.getDocument(XmlBeansUtil.getBytes(ard.getSadRequest())).getDocumentElement());
            extensions.getUnknownXMLObjects().add(sadReqElm);
        }
        if (ard.getPrincipalSelection() != null) {
            XSAny principalSelectionElm = new XSAnyBuilder().buildObject("http://id.swedenconnect.se/authn/1.0/principal-selection/ns", "PrincipalSelection", "psc");

            principalSelectionElm.setDOM(XmlUtils.getDocument(XmlBeansUtil.getBytes(ard.getPrincipalSelection())).getDocumentElement());
            extensions.getUnknownXMLObjects().add(principalSelectionElm);
        }

        return extensions;
    }

    public static SignMessageDocument getSignMessageDocument(String signMessage, boolean mustDisplay, String idpEntityId, String mimeType, Certificate idpCert, boolean encryptSignMess) {
        SignMessageDocument signMessDocument = SignMessageDocument.Factory.newInstance();
        SignMessageType signMessType = signMessDocument.addNewSignMessage();
        signMessType.setMustShow(mustDisplay);
        signMessType.setDisplayEntity(idpEntityId);
        signMessType.setMimeType(MessageMimeType.getMimeTypeFromStringVal(mimeType).getXmlMimeType());
        signMessType.setMessage(signMessage.getBytes(Charset.forName("UTF-8")));
        if (encryptSignMess) {
            if (idpCert == null) {
                return null;
            }
            try {
                signMessDocument = EncryptXml.encryptSignMessage(signMessDocument, idpCert.getPublicKey());
                ;
            } catch (Exception ex) {
                Logger.getLogger(OSUtil.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return signMessDocument;
    }

}
