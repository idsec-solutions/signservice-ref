/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import java.security.SecureRandom;
import org.opensaml.saml2.common.impl.ExtensionsBuilder;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;

/**
 *
 * @author stefan
 */
public class Builder {

    //Builders
    public static final ResponseBuilder responseBuilder = new ResponseBuilder();
    public static final AssertionBuilder assertionBuilder = new AssertionBuilder();
    public static final AttributeBuilder attributeBuilder = new AttributeBuilder();
    public static final AudienceRestrictionBuilder audienceRestrictionBuilder = new AudienceRestrictionBuilder();
    public static final AudienceBuilder audienceBuilder = new AudienceBuilder();
    public static final XSStringBuilder xsStringBuilder = new XSStringBuilder();
    public static final XSAnyBuilder xsAnyBuilder = new XSAnyBuilder();
    public static final StatusBuilder statusBuilder = new StatusBuilder();
    public static final StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
    public static final StatusMessageBuilder statusMessageBuilder = new StatusMessageBuilder();
    public static final SignatureBuilder signatureBuilder = new SignatureBuilder();
    public static final KeyInfoBuilder keyInfoBuilder = new KeyInfoBuilder();
    public static final X509DataBuilder x509DataBuilder = new X509DataBuilder();
    public static final X509CertificateBuilder x509CertificateBuilder = new X509CertificateBuilder();
    public static final ExtensionsBuilder extensionsBuilder = new ExtensionsBuilder();
    //Factories
    public static final MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
    public static final UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
    public static final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
    //Random
    public static final SecureRandom rng = new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes());

    private Builder() {
    }

}
