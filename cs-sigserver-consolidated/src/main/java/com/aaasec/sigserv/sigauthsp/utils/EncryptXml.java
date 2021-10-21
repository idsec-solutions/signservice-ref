/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import com.aaasec.sigserv.sigauthsp.deflate.XmlBeansUtil;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.w3.x2001.x04.xmlenc.EncryptedDataDocument;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import se.elegnamnden.id.csig.x11.dssExt.ns.MessageDocument;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageDocument;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageType;

/**
 *
 * @author stefan
 */
public class EncryptXml {

    private static final Logger LOG = Logger.getLogger(EncryptXml.class.getName());
    private static final String AES_ALGO = "AES";
    public static final String XML_ENCRYPTION_NS = "http://www.w3.org/2001/04/xmlenc#";
    public static final String EID2_OASIS_SIGN_EXT_NS = "http://id.elegnamnden.se/csig/1.1/dss-ext/ns";
    public static final String ENCRYPTED_DATA_TAG_NAME = "EncryptedData";
    public static final String EID2_MESSAGE_TAG_NAME = "Message";
    private static final DocumentBuilderFactory docBuilderFactory;

    static {
        org.apache.xml.security.Init.init();
        docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setNamespaceAware(true);
    }

    public static SignMessageDocument encryptSignMessage(SignMessageDocument signMessageToBeEncrypted, PublicKey kek) {
        try {
            boolean mustShow = signMessageToBeEncrypted.getSignMessage().getMustShow();
            String recipientId = signMessageToBeEncrypted.getSignMessage().getDisplayEntity();
            SignMessageType.MimeType.Enum mimeType = signMessageToBeEncrypted.getSignMessage().getMimeType();

            MessageDocument messageDoc = MessageDocument.Factory.newInstance();
            messageDoc.setMessage(signMessageToBeEncrypted.getSignMessage().getMessage());
            DocumentBuilder xmlDocBuilder = docBuilderFactory.newDocumentBuilder();
            Document messageDomDoc = xmlDocBuilder.parse(new ByteArrayInputStream(XmlBeansUtil.getBytes(messageDoc)));

            Key symmetricKey = GenerateDataEncryptionKey(AES_ALGO, 128);

            //Encrypt encryption key with public key of receipient (kek)
            String kekAlgoURI = XMLCipher.RSA_OAEP;
            XMLCipher keyCipher = XMLCipher.getInstance(kekAlgoURI);
            keyCipher.init(XMLCipher.WRAP_MODE, kek);
            EncryptedKey encryptedKey = keyCipher.encryptKey(messageDomDoc, symmetricKey);

            String algorithmURI = XMLCipher.AES_128;
            XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
            xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);

            /*
             * Setting keyinfo inside the encrypted data being prepared.
             */
            EncryptedData encryptedData = xmlCipher.getEncryptedData();
            KeyInfo keyInfo = new KeyInfo(messageDomDoc);
            keyInfo.add(encryptedKey);
            keyInfo.add(kek);
            encryptedData.setKeyInfo(keyInfo);

            /*
             * Encrypt Message element
             */
            xmlCipher.doFinal(messageDomDoc, messageDomDoc);
            Element encryptedDataElement = (Element) messageDomDoc.getElementsByTagNameNS(XML_ENCRYPTION_NS, ENCRYPTED_DATA_TAG_NAME).item(0);
            EncryptedDataDocument encDataDoc = EncryptedDataDocument.Factory.parse(encryptedDataElement);
            SignMessageDocument encSignMessageDocument = SignMessageDocument.Factory.newInstance();
            encSignMessageDocument.addNewSignMessage().addNewEncryptedMessage().setEncryptedData(encDataDoc.getEncryptedData());
            encSignMessageDocument.getSignMessage().setMustShow(mustShow);
            encSignMessageDocument.getSignMessage().setDisplayEntity(recipientId);
            encSignMessageDocument.getSignMessage().setMimeType(mimeType);
            return encSignMessageDocument;

        } catch (Exception ex) {
            LOG.log(Level.SEVERE, null, ex);
            return null;
        }

    }

    private static SecretKey GenerateDataEncryptionKey(String algorithm, int keySize) throws Exception {
        String jceAlgorithmName = algorithm;
        KeyGenerator keyGenerator
                = KeyGenerator.getInstance(jceAlgorithmName);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public static SignMessageDocument decryptSignMessage(SignMessageDocument encryptedSignMess, PrivateKey kek) {
        try {
            boolean mustShow = encryptedSignMess.getSignMessage().getMustShow();
            String recipientId = encryptedSignMess.getSignMessage().getDisplayEntity();
            SignMessageType.MimeType.Enum mimeType = encryptedSignMess.getSignMessage().getMimeType();
            Document document = getDoc(XmlBeansUtil.getBytes(encryptedSignMess));
            Element encryptedDataElement = (Element) document.getElementsByTagNameNS(XML_ENCRYPTION_NS, ENCRYPTED_DATA_TAG_NAME).item(0);

            XMLCipher xmlCipher = XMLCipher.getInstance();
            xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
            EncryptedData encData = xmlCipher.loadEncryptedData(document, encryptedDataElement);
            EncryptedKey encKey = encData.getKeyInfo().itemEncryptedKey(0);

            XMLCipher keyCipher = XMLCipher.getInstance();
            keyCipher.init(XMLCipher.UNWRAP_MODE, kek);
            Key decryptKey = keyCipher.decryptKey(encKey, encData.getEncryptionMethod().getAlgorithm());

            XMLCipher docCipher = XMLCipher.getInstance();
            docCipher.init(XMLCipher.DECRYPT_MODE, decryptKey);

            docCipher.doFinal(document, encryptedDataElement);

            SignMessageDocument tempDecDoc = SignMessageDocument.Factory.parse(document);
            MessageDocument messageDoc = MessageDocument.Factory.parse(document.getElementsByTagNameNS(EID2_OASIS_SIGN_EXT_NS, EID2_MESSAGE_TAG_NAME).item(0));

            SignMessageDocument decyptedSignMess = SignMessageDocument.Factory.newInstance();
            decyptedSignMess.addNewSignMessage().setMessage(messageDoc.getMessage());
            decyptedSignMess.getSignMessage().setMustShow(mustShow);
            decyptedSignMess.getSignMessage().setDisplayEntity(recipientId);
            decyptedSignMess.getSignMessage().setMimeType(mimeType);

            return decyptedSignMess;
        } catch (Exception ex) {
            return encryptedSignMess;
        }

    }

    public static Document getDoc(byte[] xmlData) throws IOException, SAXException, ParserConfigurationException {
        InputStream is = new ByteArrayInputStream(xmlData);
        DocumentBuilder xmlDocBuilder = docBuilderFactory.newDocumentBuilder();
        Document doc = xmlDocBuilder.parse(is);
        return doc;
    }

}
