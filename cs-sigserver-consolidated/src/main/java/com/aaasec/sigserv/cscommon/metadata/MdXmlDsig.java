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
package com.aaasec.sigserv.cscommon.metadata;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import com.aaasec.lib.crypto.xml.SigVerifyResult;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyValue;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.w3.x2000.x09.xmldsig.ReferenceType;
import org.w3.x2000.x09.xmldsig.SignatureDocument;
import org.w3.x2000.x09.xmldsig.SignatureType;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * XML Dsig functions.
 */
public class MdXmlDsig {

    public static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static DocumentBuilder documentBuilder;

    static {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        try {
            documentBuilder = dbFactory.newDocumentBuilder();
        } catch (ParserConfigurationException ex) {
            Logger.getLogger(MdXmlDsig.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        org.apache.xml.security.Init.init();

        // org.apache.xml.security.utils.Constants.setSignatureSpecNSprefix("");
    }

    public static Document signXml(InputStream docIs, PrivateKey privateKey, PublicKey pk, Node sigParent) {
        return signXml(docIs, privateKey, null, pk, sigParent);
    }

    public static Document signXml(InputStream docIs, PrivateKey privateKey, X509Certificate cert, Node sigParent) {
        return signXml(docIs, privateKey, cert, null, sigParent);

    }

    public static Document signXml(InputStream docIs, PrivateKey privateKey, X509Certificate cert, PublicKey pk, Node sigParent) {
        try {
            // Instantiate the document to be signed
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            dbFactory.setNamespaceAware(true);
            Document doc = dbFactory.newDocumentBuilder().parse(docIs);

            String id = String.valueOf(System.currentTimeMillis());

            // sign the whole contract and no signature and exclude condition1
            String xpathStr = "not(ancestor-or-self::ds:Signature)";

            {
                XMLSignature signature =
                        new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);

                if (sigParent != null) {
                    String namespaceURI = sigParent.getNamespaceURI();
                    String nodeName = sigParent.getNodeName();
                    NodeList nl = doc.getElementsByTagNameNS(namespaceURI, nodeName);
                    if (nl.getLength() > 0) {
                        Element sigObjNode = (Element) nl.item(0);
                        sigObjNode.appendChild(signature.getElement());
//                        int asdf = 0;
                    } else {
                        doc.getFirstChild().appendChild(signature.getElement());
                    }
                } else {
                    doc.getFirstChild().appendChild(signature.getElement());
                }

                signature.setId(id);

                String rootnamespace = doc.getNamespaceURI();
                boolean rootprefixed = (rootnamespace != null) && (rootnamespace.length() > 0);
                String rootlocalname = doc.getNodeName();
                Transforms transforms = new Transforms(doc);
                XPathContainer xpath = new XPathContainer(doc);

                xpath.setXPathNamespaceContext("ds", Constants.SignatureSpecNS);
                xpath.setXPath(xpathStr);
                transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
                transforms.addTransform(Transforms.TRANSFORM_XPATH,
                        xpath.getElementPlusReturns());
                signature.addDocument("", transforms, SHA256);
//                signature.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

                {
                    if (cert == null) {
                        signature.getKeyInfo().add(new KeyValue(doc, pk));
                    } else {
                        X509Data x509Data = new X509Data(doc);
                        x509Data.addCertificate(cert);
                        signature.getKeyInfo().add(x509Data);
                    }
                    signature.sign(privateKey);
                }

                //Set Id attribute value on signature
                try {
                    Node sigValueNode = signature.getElement()
                            .getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "SignatureValue").item(0);
                    Attr idAttr = doc.createAttribute("Id");
                    idAttr.setValue(id);
                    sigValueNode.getAttributes().setNamedItem(idAttr);
                } catch (Exception ex) {
                }
            }
            return doc;
        } catch (Exception ex) {
            return null;
        }
    }

    public static SigVerifyResult verifySignature(Document doc) {
        NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            return new SigVerifyResult("No Signature");
        }

        Node signatureNode = nl.item(nl.getLength() - 1);
        if (null == signatureNode) {
            return new SigVerifyResult("No Signature");
        }

        return verifySignatureElement(doc, signatureNode);
    }

    public static SigVerifyResult verifySameDocRefSignature(byte[] docBytes) {
        try {
            return verifySameDocRefSignature(getDocument(docBytes));
        } catch (Exception ex) {
            return new SigVerifyResult("Xml parsing error");
        }

    }

    public static SigVerifyResult verifySameDocRefSignature(Document doc) {
        NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            return new SigVerifyResult("No Signature");
        }

        boolean sameDocRef = false;
        Node signatureNode = null;
        for (int i = 0; i < nl.getLength(); i++) {
            signatureNode = nl.item(i);
            try {
                SignatureType sig = SignatureDocument.Factory.parse(signatureNode).getSignature();
                ReferenceType[] referenceArray = sig.getSignedInfo().getReferenceArray();
                for (ReferenceType ref : referenceArray) {
                    String refUri = ref.getURI();
                    if (refUri.equals("")) {
                        sameDocRef = true;
                        break;
                    }
                }
            } catch (Exception ex) {
            }
        }

        if (!sameDocRef) {
            return new SigVerifyResult("No signature with same document reference found");
        }

        return verifySignatureElement(doc, signatureNode);
    }

    public static SigVerifyResult verifySignatureID(byte[] docBytes, String id) {
        try {
            return verifySignatureID(getDocument(docBytes), id);
        } catch (Exception ex) {
            return new SigVerifyResult("Xml parsing error");
        }
    }

    public static SigVerifyResult verifySignatureID(Document doc, String id) {
        NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            return new SigVerifyResult("No Signature");
        }

        boolean idSignature = false;
        Node signatureNode = null;
        for (int i = 0; i < nl.getLength(); i++) {
            signatureNode = nl.item(i);
            try {
                SignatureType sig = SignatureDocument.Factory.parse(signatureNode).getSignature();
                ReferenceType[] referenceArray = sig.getSignedInfo().getReferenceArray();
                for (ReferenceType ref : referenceArray) {
                    String refUri = ref.getURI();
                    if (refUri.startsWith("#")
                            && refUri.length() == id.length() + 1
                            && id.length() > 0
                            && refUri.endsWith(id)) {
                        idSignature = true;
                        break;
                    }
                }
            } catch (Exception ex) {
            }
        }

        if (!idSignature) {
            return new SigVerifyResult("No signature with appropriate ID reference found");
        }

        return verifySignatureElement(doc, signatureNode);
    }

    public static SigVerifyResult verifySignatureElement(Document doc, Node signatureNode) {
        XMLSignature xmlSig = null;
        try {
            xmlSig = new XMLSignature((Element) signatureNode, "");
        } catch (Exception ex) {
            return new SigVerifyResult("No Signature");
        }
        KeyInfo keyInfo = xmlSig.getKeyInfo();
        PublicKey pk = null;
        X509Certificate cert = null;
        try {
            cert = keyInfo.getX509Certificate();
            pk = cert.getPublicKey();
        } catch (Exception ex) {
            try {
                pk = keyInfo.getPublicKey();
            } catch (Exception ex1) {
            }
        }

        if (pk == null) {
            return new SigVerifyResult("No Public Key");
        }
        boolean coreValidity;
        try {
            coreValidity = xmlSig.checkSignatureValue(pk);
        } catch (XMLSignatureException ex) {
            return new SigVerifyResult("XML signature parse error: " + ex.getMessage());
        }

        if (coreValidity) {
            return new SigVerifyResult(cert);
        }
        return new SigVerifyResult(cert, "Core Signature validation failure", coreValidity);
    }

    private static Document getDocument(byte[] docBytes) throws ParserConfigurationException, SAXException, IOException {
        
        Document doc = documentBuilder.parse(new ByteArrayInputStream(docBytes));
        return doc;
    }
}
