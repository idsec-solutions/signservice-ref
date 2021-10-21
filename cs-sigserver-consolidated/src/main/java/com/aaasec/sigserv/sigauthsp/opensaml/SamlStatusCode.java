/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

/**
 *
 * @author stefan
 */
public enum SamlStatusCode {

    /**
     * Top-Level status code. The request succeeded. Additional information MAY
     * be returned in the StatusMessage and/or StatusDetail elements
     */
    Success("urn:oasis:names:tc:SAML:2.0:status:Success"),
    /**
     * Top-Level status code. The request could not be performed due to an error
     * on the part of the requester.
     */
    RequesterError("urn:oasis:names:tc:SAML:2.0:status:Requester"),
    /**
     * Top-Level status code. The request could not be performed due to an error
     * on the part of the SAML responder or SAML authority.
     */
    ResponserError("urn:oasis:names:tc:SAML:2.0:status:Responder"),
    /**
     * Top-Level status code. The SAML responder could not process the request
     * because the version of the request message was incorrect.
     */
    VersionMismatch("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"),
    /**
     * Second-level status Code. The responding provider was unable to
     * successfully authenticate the principal.
     */
    AuthnFailed("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"),
    /**
     * Second-level status Code. Unexpected or invalid content was encountered
     * within a Attribute or AttributeValue element.
     */
    InvalidAttrNameOrValue("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"),
    /**
     * Second-level status Code. The responding provider cannot or will not support the requested name
     * identifier policy.
     */
    InvalidNameIDPolicy("urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"),
    /**
     * Second-level status Code. The specified authentication context requirements
     * cannot be met by the responder.
     */
    NoAuthnContext("urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"),
    /**
     * Second-level status Code. Used by an intermediary to indicate that none
     * of the supported identity provider Loc elements in an IDPList can be
     * resolved or that none of the supported identity providers are available.
     */
    NoAvailableIDP("urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"),
    /**
     * Second-level status Code. Indicates the responding provider cannot
     * authenticate the principal passively, as has been requested.
     */
    NoPassive("urn:oasis:names:tc:SAML:2.0:status:NoPassive"),
    /**
     * Second-level status Code. Used by an intermediary to indicate that none
     * of the identity providers in an IDPList are supported by the intermediary.
     */
    NoSupportedIDP("urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"),
    /**
     * Second-level status Code. Used by a session authority to indicate to a
     * session participant that it was not able to propagate logout to all other
     * session participants.
     */
    PartialLogout("urn:oasis:names:tc:SAML:2.0:status:PartialLogout"),
    /**
     * Second-level status Code. Indicates that a responding provider cannot
     * authenticate the principal directly and is not permitted to proxy the
     * request further.
     */
    ProxyCountExceeded("urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"),
    /**
     * Second-level status Code. The SAML responder or SAML authority is able to
     * process the request but has chosen not to respond. This status code MAY
     * be used when there is concern about the security context of the request
     * message or the sequence of request messages received from a particular
     * requester.
     */
    RequestDenied("urn:oasis:names:tc:SAML:2.0:status:RequestDenied"),
    /**
     * Second-level status Code. The SAML responder or SAML authority does not
     * support the request.
     */
    RequestUnsupported("urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"),
    /**
     * Second-level status Code. The SAML responder cannot process any requests
     * with the protocol version specified in the request.
     */
    RequestVersionDeprecated("urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"),
    /**
     * Second-level status Code. The SAML responder cannot process the request
     * because the protocol version specified in the request message is a major
     * upgrade from the highest protocol version supported by the responder.
     */
    RequestVersionTooHigh("urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"),
    /**
     * Second-level status Code. The SAML responder cannot process the request
     * because the protocol version specified in the request message is too low.
     */
    RequestVersionTooLow("urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"),
    /**
     * Second-level status Code. The resource value provided in the request
     * message is invalid or unrecognized.
     */
    ResourceNotRecognized("urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"),
    /**
     * Second-level status Code. The response message would contain more elements
     * than the SAML responder is able to return.
     */
    TooManyResponses("urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"),
    /**
     * Second-level status Code. An entity that has no knowledge of a particular
     * attribute profile has been presented with an attribute drawn from that
     * profile.
     */
    UnknownAttrProfile("urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"),
    /**
     * Second-level status Code. The responding provider does not recognize the
     * principal specified or implied by the request.
     */
    UnknownPrincipal("urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"),
    /**
     * Second-level status Code. The SAML responder cannot properly fulfill the
     * request using the protocol binding specified in the request.
     */
    UnsupportedBinding("urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding");

    String uri;

    private SamlStatusCode(String uri) {
        this.uri = uri;
    }

    public String getUri() {
        return uri;
    }

}
