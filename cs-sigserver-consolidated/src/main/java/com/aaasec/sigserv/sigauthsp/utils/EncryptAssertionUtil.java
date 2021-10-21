package com.aaasec.sigserv.sigauthsp.utils;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.xml.encryption.*;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;

public class EncryptAssertionUtil {

    public static void encrypt(Response response, Credential receiverCredential) throws NoSuchAlgorithmException, KeyException, EncryptionException {
        Credential symmetricCredential = SecurityHelper.getSimpleCredential(
                SecurityHelper.generateSymmetricKey(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128));

        EncryptionParameters encParams = new EncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
        encParams.setEncryptionCredential(symmetricCredential);

        KeyEncryptionParameters kek = new KeyEncryptionParameters();
        kek.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        kek.setEncryptionCredential(receiverCredential);

        Encrypter encrypter = new Encrypter(encParams, kek);
        encrypter.setKeyPlacement(KeyPlacement.INLINE);

        EncryptedAssertion encrypted = encrypter.encrypt(response.getAssertions().get(0));
        response.getEncryptedAssertions().add(encrypted);

        response.getAssertions().clear();
    }

    public static Assertion decrypt(EncryptedAssertion enc, Credential credential) throws DecryptionException {
        KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);
        ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
        encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());
        Decrypter decrypter = new Decrypter(null, keyResolver, encryptedKeyResolver);
        return decrypter.decrypt(enc);
    }

}
