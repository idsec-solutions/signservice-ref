package com.aaasec.sigserv.xmlsign;

import com.aaasec.lib.crypto.xml.XmlUtils;
import org.w3c.dom.Document;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignedXmlDoc {

  public Document doc;
  public byte[] sigDocBytes;

  public SignedXmlDoc(Document doc) {
    this.doc = doc;
    this.sigDocBytes = XmlUtils.getCanonicalDocText(doc);
  }



}