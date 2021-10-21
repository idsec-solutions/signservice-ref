/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.deflate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.xml.util.Base64;

/**
 *
 * @author stefan
 */
public class SAMLMessageDecoder {

    public static InputStream decodeMessage(String message) throws MessageDecodingException {
        //log.debug("Base64 decoding and inflating SAML message");

        byte[] decodedBytes = Base64.decode(message);
        if (decodedBytes == null) {
            //log.error("Unable to Base64 decode incoming message");
            throw new MessageDecodingException("Unable to Base64 decode incoming message");
        }

        try {
            ByteArrayInputStream bytesIn = new ByteArrayInputStream(decodedBytes);
            InflaterInputStream inflater = new InflaterInputStream(bytesIn, new Inflater(true));
            return inflater;
        } catch (Exception e) {
            //log.error("Unable to Base64 decode and inflate SAML message", e);
            throw new MessageDecodingException("Unable to Base64 decode and inflate SAML message", e);
        }
    }
    

}
