package com.aaasec.sigserv.xmlsign;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.xpath.XPathExpressionException;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NodeXMLSignatureLocation {

  private Node parentNode;
  private final ChildPosition childPosition;

  public NodeXMLSignatureLocation() {
    this.childPosition = ChildPosition.LAST;
  }

  public NodeXMLSignatureLocation(ChildPosition childPosition) {
    this.childPosition = childPosition;
  }

  public NodeXMLSignatureLocation(Node parentNode, ChildPosition childPosition) throws XPathExpressionException {
    this.parentNode = parentNode;
    this.childPosition = childPosition;
  }

  public void insertSignature(Element signature, Document document) throws XPathExpressionException {
    boolean sameOwner = XMLUtils.getOwnerDocument(signature) == document;
    Node signatureNode = sameOwner ? signature : document.importNode(signature, true);
    if (parentNode == null) {
      parentNode = document.getDocumentElement();
    }
    if (((Node)parentNode).getNodeType() == 9) {
      parentNode = ((Document)parentNode).getDocumentElement();
    }

    if (ChildPosition.LAST == childPosition ) {
      ((Node)parentNode).appendChild((Node)signatureNode);
    } else {
      ((Node)parentNode).insertBefore((Node)signatureNode, ((Node)parentNode).getFirstChild());
    }
  }

  /**
   * Enum for indicating the point within a selected parent node.
   */
  public enum ChildPosition {
    FIRST, LAST
  }

}
