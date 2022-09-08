package com.aaasec.sigserv.xmlsign;

import com.aaasec.lib.crypto.xml.XmlUtils;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import com.aaasec.sigserv.xmlsign.sigcommons.DefaultXMLSigner;
import com.aaasec.sigserv.xmlsign.sigcommons.XMLSignerResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SigComXMLSign {

  public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  public static final String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
  public static final String RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
  public static final String ECDSA_SHA1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
  public static final String ECDSA_SHA224 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
  public static final String ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
  public static final String ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
  public static final String ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
  // From SignatureMethod
  public static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  // From DigestMethod
  public static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
  public static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";


  public static XMLSignerResult signXmlDoc(Document tbsDoc, PrivateKey key, List<X509Certificate> signerChain, Node sigParent, boolean append, boolean addXpath)
    throws XPathExpressionException, SignatureException {

    SimplePkiCredential pkiCredential = new SimplePkiCredential(signerChain, key);
    DefaultXMLSigner xmlSigner = new DefaultXMLSigner(pkiCredential);

    if (sigParent != null) {
      NodeList sigParentNodeList = tbsDoc.getElementsByTagNameNS(sigParent.getNamespaceURI(), sigParent.getLocalName());
      if (sigParentNodeList.getLength() > 0) {
        Node sigParentNode = sigParentNodeList.item(0);
        NodeXMLSignatureLocation signatureLocation = new NodeXMLSignatureLocation(sigParentNode,
          append ? NodeXMLSignatureLocation.ChildPosition.LAST : NodeXMLSignatureLocation.ChildPosition.FIRST);
        xmlSigner.setSignatureLocation(signatureLocation);
      }
    }
    return xmlSigner.sign(tbsDoc);
  }

  public static SignedXmlDoc getSignedXML(byte[] xmlData, PrivateKey key, iaik.x509.X509Certificate signerCert, Node sigParent, boolean append, boolean addXpath)
    throws CertificateEncodingException {
    return getSignedXML(xmlData, key, CertificateUtils.getCertificate(signerCert.getEncoded()), sigParent, append, addXpath);

  }
  public static SignedXmlDoc getSignedXML(byte[] xmlData, PrivateKey key, X509Certificate signerCert, Node sigParent, boolean append, boolean addXpath)
    throws CertificateEncodingException, XPathExpressionException, SignatureException, IOException,
    ParserConfigurationException, SAXException {
    List<X509Certificate> chain = Collections.singletonList(signerCert);
    Document tbsDocument = XmlUtils.getDocument(xmlData);

    XMLSignerResult xmlSignerResult = signXmlDoc(tbsDocument, key, chain, sigParent, append, addXpath);
    return new SignedXmlDoc(xmlSignerResult.getSignedDocument());
  }

}
