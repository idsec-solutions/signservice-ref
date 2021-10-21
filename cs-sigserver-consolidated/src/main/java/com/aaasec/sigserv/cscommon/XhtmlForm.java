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
package com.aaasec.sigserv.cscommon;

/**
 * Generates XHTML forms for sign requests and responses
 */
public class XhtmlForm implements Constants{
    

    private static final String[] formHeadLines = new String[]{
        "<?xml version='1.0' encoding='UTF-8'?>",
        "<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.1//EN' 'http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd'>",
        "<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en'>",
        "<body onload='document.forms[0].submit()'>",
        "<noscript>",
        "<p><strong>Note:</strong> Since your browser does not support JavaScript,",
        "you must press the Continue button once to proceed.</p>",
        "</noscript>",};
    private static final String[] formEndLines = new String[]{
        "</div>",
        "<noscript>",
        "<div>",
        "<input type='submit' value='Continue'/>",
        "</div>",
        "</noscript>",
        "</form>",
        "</body>",
        "</html>"
    };
    private static final String xhtmlStart;
    private static final String xhtmlEnd;

    static {
        StringBuilder b = new StringBuilder();
        for (String line : formHeadLines) {
            b.append(line).append("\n");
        }
        xhtmlStart = b.toString();
        b = new StringBuilder();
        for (String line : formEndLines) {
            b.append(line).append("\n");
        }
        xhtmlEnd = b.toString();
    }

    public static String getSignXhtmlForm(Type type, String url, byte[] xmlData, String nonce) {
        return xhtmlStart + getParameters(url, type.formType, xmlData, nonce) + xhtmlEnd;
    }

    private static String getParameters(String url, String name, byte[] value, String nonce) {
        StringBuilder b = new StringBuilder();
        b.append("<form action='");
        b.append(url);
        b.append("' method='post'>").append("\n");
        b.append("<div>").append("\n");
        // Binding
        b.append(getParameterField("Binding", PROTOCOL_BINDING));        
        // Nonce
        b.append(getParameterField("RelayState", nonce));
        // request/response field
        b.append(getParameterField(name, Base64Coder.encode(value)));
        

        return b.toString();
    }

    private static String getParameterField(String parameterName, char[] data) {
        return getParameterField(parameterName, String.valueOf(data));
    }

    private static String getParameterField(String parameterName, String data) {
        String field = "<input type='hidden' name='"
                + parameterName
                + "' value='"
                + data + "'/>\n";
        return field;
    }

    public enum Type {

        SIG_REQUEST_FORM("EidSignRequest"), SIG_RESPONSE_FORM("EidSignResponse");
        public final String formType;

        private Type(String formType) {
            this.formType = formType;
        }
    }
}
