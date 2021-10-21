/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.centralsig;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

/**
 *
 * @author stefan
 */
public class PkCrypto {

    public static byte[] rsaVerify(byte[] data, PublicKey pubKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] cipherData = cipher.doFinal(data);
        return cipherData;
    }

    public static byte[] rsaSign(byte[] data, PrivateKey privKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] cipherData = cipher.doFinal(data);
        return cipherData;
    }

    public static byte[] rsaSignEncodedMessage(byte[] data, PrivateKey privKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] cipherData = cipher.doFinal(data);
        return cipherData;
    }

    public static boolean ecdsaVerifyDigest(byte[] digest, EcdsaSigValue signature, PublicKey pubKey) throws InvalidKeyException {
        ECDSASigner ecdsa = new ECDSASigner();
        CipherParameters param = ECUtil.generatePublicKeyParameter(pubKey);
        ecdsa.init(false, param);
        return ecdsa.verifySignature(digest, signature.getR(), signature.getS());
    }

    public static EcdsaSigValue ecdsaSignData(byte[] data, PrivateKey privKey, SupportedSigAlgoritm sigAlgo) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException {
        Signature ecdsaSigner = Signature.getInstance(sigAlgo.name(), "BC");
        ecdsaSigner.initSign(privKey, new SecureRandom(String.valueOf(System.currentTimeMillis()).getBytes()));
        ecdsaSigner.update(data);
        byte[] asn1Signature = ecdsaSigner.sign();
        ASN1InputStream a1i = new ASN1InputStream(asn1Signature);
        ASN1Sequence a1s = ASN1Sequence.getInstance(a1i.readObject());
        EcdsaSigValue sigVal = new EcdsaSigValue(a1s);
        return sigVal;
    }

    public static boolean ecdsaVerifySignedData(byte[] data, EcdsaSigValue signature, PublicKey pubKey, DigestAlgorithm digestAlgo) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        SupportedSigAlgoritm sigAlgo = SupportedSigAlgoritm.getAlgoFromTypeAndHash(digestAlgo, PublicKeyType.EC);
        EcdsaSigValue sigVal = EcdsaSigValue.getInstance(signature);
        byte[] asn1Signature = sigVal.toASN1Object().getEncoded();
        Signature ecdsaSigner = Signature.getInstance(sigAlgo.name(), "BC");
        ecdsaSigner.initVerify(pubKey);
        ecdsaSigner.update(data);
        return ecdsaSigner.verify(asn1Signature);
    }
}
