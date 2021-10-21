/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.enums;

import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageType.MimeType;

/**
 *
 * @author stefan
 */
public enum MessageMimeType {
    text("text", MimeType.TEXT),
    html("text/html", MimeType.TEXT_HTML),
    markdown("text/markdown", MimeType.TEXT_MARKDOWN);
    
    String mimeType;
    MimeType.Enum xmlMimeType;

    private MessageMimeType(String mimeType, MimeType.Enum xmlMimeType) {
        this.mimeType = mimeType;
        this.xmlMimeType = xmlMimeType;
    }

    public String getMimeType() {
        return mimeType;
    }

    public MimeType.Enum getXmlMimeType() {
        return xmlMimeType;
    }
    
    public static MessageMimeType getMimeTypeFromStringVal(String mimeTypeString){
        if (mimeTypeString.equalsIgnoreCase(MessageMimeType.html.getMimeType())){
            return MessageMimeType.html;
        }
        if (mimeTypeString.equalsIgnoreCase(MessageMimeType.markdown.getMimeType())){
            return MessageMimeType.markdown;
        }
        return MessageMimeType.text;
    }    
}
