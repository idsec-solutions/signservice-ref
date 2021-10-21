/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigserver;

import com.aaasec.lib.crypto.xml.XmlBeansUtil;
import com.aaasec.sigserv.cscommon.data.AuthData;
import com.aaasec.sigserv.cscommon.enums.ContextAttributes;
import com.aaasec.sigserv.cscommon.enums.SamlAttribute;
import com.aaasec.sigserv.cssigapp.models.RequestModel;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;
import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import com.aaasec.sigserv.sigauthsp.opensaml.ApAssertion;
import com.aaasec.sigserv.sigauthsp.utils.ApResponseHandler;
import com.aaasec.sigserv.sigauthsp.utils.OsSigvalResult;

/**
 *
 * @author stefan
 */
public class RequestModelFactory {

    boolean error = false;
    String errorMsg = "General error";
    String displayName;
    String idAttr;
    String idAttrVal;
    String idpEntityId;
    List<String> authnLoaList;
    private static final java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("infoText");
    private static final Logger LOG = Logger.getLogger(RequestModelFactory.class.getName());

    public RequestModelFactory() {
    }

    public RequestModel getRequestModel(ApResponseHandler respHandler) {
        LOG.fine("Parsing user identity from SAML response");
        RequestModel req = new RequestModel();
        try {
            Response response = respHandler.getResponse();
            req.setId(getResponseId(response.getInResponseTo()));
            ApAssertion assertion = getAssertion(respHandler);
            getAuthenticationData(assertion, req, respHandler);
            if (!checkValidity(req)) {
                errorMsg = "ValidityCheckFailure";
                LOG.warning(errorMsg);
                return null;
            }
            
            // Check signature if assertion is signed. If assertion was not signed, then reaching this point means
            // that the response had a valid signature.
            OsSigvalResult assertionSignatureValidation = respHandler.getAssertionSignatureValidation();
            if (assertionSignatureValidation.isSigned()){
                if (!assertionSignatureValidation.isValidSignature()){
                    error = true;
                    errorMsg = "invalid Asseriton signature";
                    LOG.warning(errorMsg);
                    return null;
                }
            }

        } catch (Exception ex) {
            LOG.warning("Failure to parse user data from SAML response: " + ex.getMessage());
            return null;
        }

        LOG.fine("Authenticated user with ID: " + req.getAuthData().getId());
        return req;
    }

    public static String getResponseId(String id) {
        if (id == null || id.length() < 2) {
            throw new NullPointerException("Insufficent InResponseTo id");
        }
        if (id.startsWith("_")) {
            return id.substring(1);
        }
        return id;
    }

    private ApAssertion getAssertion(ApResponseHandler respHandler) {
        ApAssertion assertion = respHandler.getDecryptedAssertion();
        if (assertion == null || assertion.obj == null) {
            throw new NullPointerException("Null Assertion in IdP response");
        }
        return assertion;
    }

    private void getAuthenticationData(ApAssertion assertion, RequestModel req, ApResponseHandler respHandler) throws XmlException {
        List<List<String>> contextAttrList = getContext(assertion, req);
        List<List<String>> idAttrList = getAttributes(assertion.obj.getAttributeStatements());

        AuthData authData = new AuthData("saml", displayName, contextAttrList, idAttrList, idpEntityId, idAttr, idAttrVal, authnLoaList);
        byte[] assertionBytes = XmlBeansUtil.getBytes(XmlObject.Factory.parse(assertion.getXmlDoc()));
        ArrayList<byte[]> assertionList = new ArrayList<byte[]>();
        assertionList.add(assertionBytes);
        authData.setAssertions(assertionList);
        req.setAuthData(authData);
    }

    private List<List<String>> getContext(ApAssertion assertion, RequestModel req) {
        // Identity-Provider, Authentication-Method, Authentication-Instant, Assertion-ID
        List<List<String>> contextAttrList = new ArrayList<List<String>>();
        authnLoaList = new ArrayList<>();

        try {
            // IdpEntityId
            idpEntityId = assertion.obj.getIssuer().getValue();
            contextAttrList.add(getAttrInfoList(ContextAttributes.identityProvider.getAttrName(), idpEntityId));

            // Authentication-Method
            List<AuthnStatement> authnStatements = assertion.obj.getAuthnStatements();
            for (AuthnStatement authnStatement : authnStatements){
                String authnContextClassRef = authnStatement.getAuthnContext().getAuthnContextClassRef().getDOM().getTextContent();
                authnLoaList.add(authnContextClassRef);
                contextAttrList.add(getAttrInfoList(ContextAttributes.authContextClass.getAttrName(), authnContextClassRef));
                LOG.fine("Processing user authentication with AuthnContextClassRef: " + authnContextClassRef);
            }
            // Authentication-Instant
            Date authnInstant = authnStatements.get(0).getAuthnInstant().toDate();
            req.setAuthInstant(authnInstant);
            Date issueInstant = assertion.obj.getIssueInstant().toDate();
            req.setIssueIntant(issueInstant);
            contextAttrList.add(getAttrInfoList(ContextAttributes.authInstant.getAttrName(), authnInstant.toString()));

            // Assertion-ID
            String assertionId = assertion.obj.getID();
            contextAttrList.add(getAttrInfoList(ContextAttributes.assertionId.getAttrName(), assertionId));
        } catch (Exception ex) {
            LOG.warning("Error processing assertion - " + ex.getMessage());
        }
        return contextAttrList;
    }

    private List<List<String>> getAttributes(List<AttributeStatement> attributeStatements) {
        List<List<String>> userAttrList = new ArrayList<List<String>>();
        List<List<String>> idAttrList = new ArrayList<List<String>>();
        List<List<String>> dispNameAttrList = new ArrayList<List<String>>();
        List<SamlAttribute> displayNamedAttributes = SamlAttribute.getDisplayNamedAttributes();
        List<SamlAttribute> idAttributes = SamlAttribute.getIdAttributes();
        String givenName = null;
        String surname = null;

        //Traverse attributes in SAML assertion
        try {
            for (AttributeStatement attrStatement : attributeStatements) {
                for (Attribute attr : attrStatement.getAttributes()) {
                    String name = attr.getName();
                    List<XMLObject> attributeValues = attr.getAttributeValues();
                    SamlAttribute samlAttr = SamlAttribute.getAttributeFromSamlName(name);
                    if (samlAttr != null) {
                        List<String> attrInfoList = getAttrInfoList(samlAttr.name(), getValueStr(attributeValues));
                        userAttrList.add(attrInfoList);
                        // check for id attribute
                        if (idAttributes.contains(samlAttr)) {
                            idAttrList.add(attrInfoList);
                        }
                        if (displayNamedAttributes.contains(samlAttr)) {
                            dispNameAttrList.add(attrInfoList);
                        }
                        if (samlAttr.equals(SamlAttribute.givenName)) {
                            givenName = attrInfoList.get(2);
                        }
                        if (samlAttr.equals(SamlAttribute.sn)) {
                            surname = attrInfoList.get(2);
                        }
                    }
                }
            }

            if (idAttrList.isEmpty()) {
                error = true;
                errorMsg = "No matching unique ID attribute";
                return null;
            }

            List<String> idAttrData = getPreferredAttr(idAttrList, idAttributes);
            idAttr = idAttrData.get(0);
            idAttrVal = idAttrData.get(2);

            if (dispNameAttrList.isEmpty()) {
                displayName = getGnSnDisplayName(givenName, surname);
                if (displayName == null) {
                    error = true;
                    errorMsg = "No displayName";
                    return null;
                }
            } else {
                List<String> dispNameAttr = getPreferredAttr(dispNameAttrList, displayNamedAttributes);
                displayName = dispNameAttr.get(2);
            }
        } catch (Exception ex) {
            error = true;
            errorMsg = "failed to extract valid user data";
        }

        return userAttrList;
    }

    private static List<String> getAttrInfoList(String attr, Object attrObject) {
        String attrValue = (attrObject instanceof String) ? (String) attrObject : attrObject.toString();
        List<String> valueList = new ArrayList<String>();
        valueList.add(attr);
        valueList.add(getInfoText(attr));
        valueList.add(attrValue);
        return valueList;
    }

    private static String getInfoText(String str) {
        String infoTxt = str;
        try {
            infoTxt = bundle.getString(str);
        } catch (Exception ex) {
        }
        return infoTxt;
    }

    private static String utf8(String isoStr) {
        if (isoStr == null) {
            return "";
        }
        byte[] bytes = isoStr.getBytes(Charset.forName("ISO-8859-1"));
        return new String(bytes, Charset.forName("UTF-8"));
    }

    private static String getValueStr(List<XMLObject> attributeValues) {
        StringBuilder b = new StringBuilder();
        Iterator<XMLObject> iterator = attributeValues.iterator();
        while (iterator.hasNext()) {
            XMLObject xmlVal = iterator.next();
            b.append(xmlVal.getDOM().getTextContent());
            if (iterator.hasNext()) {
                b.append("; ");
            }
        }
        return b.toString();
    }

    private String getGnSnDisplayName(String givenName, String surname) {
        if (givenName != null && surname != null) {
            return givenName + " " + surname;
        }

        if (surname != null) {
            return surname;
        }

        if (givenName != null) {
            return givenName;
        }

        return null;

    }

    private List<String> getPreferredAttr(List<List<String>> attrList, List<SamlAttribute> prefAttrList) {
        for (SamlAttribute samlAttr : prefAttrList) {
            for (List<String> attrData : attrList) {
                if (samlAttr.name().equals(attrData.get(0))) {
                    return attrData;
                }
            }
        }
        return null;
    }

    private boolean checkValidity(RequestModel req) {
        Calendar notBefore = Calendar.getInstance();
        notBefore.add(Calendar.SECOND, -120);
        Calendar issueInstant = Calendar.getInstance();
        issueInstant.setTime(req.getIssueIntant());
        Calendar authInstant = Calendar.getInstance();
        authInstant.setTime(req.getAuthInstant());
        
        // Check that assertion was not issued more than 30 sec ago
        if (issueInstant.before(notBefore)){
            return false;
        }
        
        // Check that authenticaiton was not more than 10 before issue instant
        notBefore.setTime(req.getIssueIntant());
        notBefore.add(Calendar.SECOND, -120);
        if (authInstant.before(notBefore)){
            return false;
        }
        return true;
    }

}
