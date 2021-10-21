/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.models;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author stefan
 */
public class KeyStoreBundle {
    KeyStore keyStore;
    char[] password;
    String alias;

    public KeyStoreBundle(KeyStore keyStore, char[] password, String alias) {
        this.keyStore = keyStore;
        this.password = password;
        this.alias = alias;
    }
    public KeyStoreBundle(KeyStore keyStore, char[] password) {
        this.keyStore = keyStore;
        this.password = password;
        
        try {
            this.alias = keyStore.aliases().nextElement();
        } catch (KeyStoreException ex) {
            Logger.getLogger(KeyStoreBundle.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public KeyStoreBundle() {
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public char[] getPassword() {
        return password;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
    
    public PrivateKey getPrivate() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException{
        return (PrivateKey) keyStore.getKey(alias, password);
    }
    
    public Certificate getCertificate() throws KeyStoreException{
        return keyStore.getCertificate(alias);        
    }
    
}
