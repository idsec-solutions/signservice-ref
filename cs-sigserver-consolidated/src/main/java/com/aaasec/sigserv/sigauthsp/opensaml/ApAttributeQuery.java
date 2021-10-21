/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.opensaml;

import org.opensaml.saml2.core.AttributeQuery;

/**
 *
 * @author stefan
 */
public class ApAttributeQuery extends AbstractOpenSamlObj<AttributeQuery> {

    public ApAttributeQuery() {
        super(AttributeQuery.DEFAULT_ELEMENT_NAME);
    }

    public ApAttributeQuery(AttributeQuery obj) {
        super(obj, AttributeQuery.DEFAULT_ELEMENT_NAME);
    }

}
