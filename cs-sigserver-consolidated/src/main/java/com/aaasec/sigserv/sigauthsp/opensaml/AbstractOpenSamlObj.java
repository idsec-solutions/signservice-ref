/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * @author stefan
 * @param <E> The Open SAML object class
 */
public abstract class AbstractOpenSamlObj<E extends XMLObject> {

    public E obj;
    private final QName qName;
    private static final DocumentBuilderFactory docBuilderFactory;

    static {
        docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setNamespaceAware(true);
    }

    public AbstractOpenSamlObj(QName qName) {
        this.qName = qName;
        init();
    }

    public AbstractOpenSamlObj(E obj, QName qName) {
        this.obj = obj;
        this.qName = qName;
    }

    private void init() {
        this.obj = (E) Builder.builderFactory.getBuilder(qName).buildObject(qName);
    }

    public Element getElement() {
        try {
            Marshaller marshaller = Builder.marshallerFactory.getMarshaller(obj);
            return marshaller.marshall(obj);
        } catch (MarshallingException ex) {
            Logger.getLogger(AbstractOpenSamlObj.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    public Document getXmlDoc() {
        try {
            Marshaller marshaller = Builder.marshallerFactory.getMarshaller(obj);
            DocumentBuilder xmlDocBuilder = docBuilderFactory.newDocumentBuilder();
            Document xmlDoc = xmlDocBuilder.newDocument();
            marshaller.marshall(obj, xmlDoc);
            return xmlDoc;
        } catch (Exception ex) {
            Logger.getLogger(AbstractOpenSamlObj.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    protected String getNewID() {
        return "_" + new BigInteger(128, Builder.rng).toString(16);
    }

}
