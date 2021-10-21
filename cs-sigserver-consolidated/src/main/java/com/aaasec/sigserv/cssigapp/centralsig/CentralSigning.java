/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.centralsig;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignTaskDataType.SigType;

/**
 *
 * @author stefan
 */
public class CentralSigning {

    public static byte[] centralSign(SupportedSigAlgoritm sigAlgo, byte[] toBeSignedBytes, PrivateKey privKey, SigType.Enum sigType) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        try {
            MessageDigest md = MessageDigest.getInstance(sigAlgo.getDigestAlgo().getName());
            md.update(toBeSignedBytes);
            byte[] hashValue = md.digest();

            switch (sigAlgo.getPkAlgoType()) {
                case EC:
                    EcdsaSigValue ecdsaSigVal = PkCrypto.ecdsaSignData(toBeSignedBytes, privKey, sigAlgo);
                    if (sigType.equals(SigType.XML)){
                        return ecdsaSigVal.toByteArray(256);
                    }
                    return ecdsaSigVal.getDEREncodedSigValue();
                case RSA:
                    switch (sigAlgo){
                    case SHA224WITHRSAPSS:
                    case SHA256WITHRSAPSS:
                    case SHA512WITHRSAPSS:
                        try {
                            int modLen = ((RSAKey) privKey).getModulus().bitLength();
                            PSSPadding pssPadding = new PSSPadding(modLen, sigAlgo.getDigest());
                            pssPadding.update(toBeSignedBytes);
                            byte[] emBytes = pssPadding.generateSignatureEncodedMessage();
                            return PkCrypto.rsaSignEncodedMessage(emBytes, privKey);
                        } catch (Exception ex){
                            Logger.getLogger(CentralSigning.class.getName()).log(Level.SEVERE, null, ex);
                            return  null;
                        }
                        default:
                            byte[] rsaSign = PkCrypto.rsaSign(getRSAPkcs1DigestInfo(sigAlgo.getDigestAlgo(), hashValue), privKey);
                            return rsaSign;
                    }
                case Unknown:
                    break;
                default:
                    throw new AssertionError(sigAlgo.getPkAlgoType().name());

            }

        } catch (Exception e) {
            Logger.getLogger(CentralSigning.class.getName()).log(Level.SEVERE, null, e);
        }
        return null;
    }

    /**
     * Updates the ESSSigningCertificate signed attribute. If such attribute was present in the sign request or the signature is a PAdES
     * signature, a V2 attribute will always be added to the signature.
     * @param signedAttrBytes the bytes of signed attributes provided in the sign request
     * @param cert signing certificate
     * @param digestAlgo hash algorithm used to hash the signing certificate
     * @param includeIssuerSerial true if the ESSSigningCertificate attribute should contain the issuer serial information
     * @param pades true if this is a PAdES signature
     * @return DER encoded signed attributes
     * @throws IOException on error
     * @throws NoSuchAlgorithmException on error
     * @throws CertificateException on error
     */
    public static byte[] updateESSSignCertAttribute(byte[] signedAttrBytes, Certificate cert, DigestAlgorithm digestAlgo, boolean includeIssuerSerial, boolean pades) throws IOException, NoSuchAlgorithmException, CertificateException {
        ASN1Set inAttrSet = ASN1Set.getInstance(new ASN1InputStream(signedAttrBytes).readObject());
        ASN1EncodableVector newSigAttrSet = new ASN1EncodableVector();

        boolean addedSignedAttrs = false;
        for (int i = 0; i < inAttrSet.size(); i++) {
            Attribute attr = Attribute.getInstance(inAttrSet.getObjectAt(i));

            if (isEssSigCertAttr(attr)) {
                //replace the existing signed signer cert attribute with a new one.
                newSigAttrSet.add(new DERSequence(getSignedCertAttr(digestAlgo, cert, includeIssuerSerial)));
                addedSignedAttrs = true;
            } else {
                newSigAttrSet.add(attr);
            }
        }

        //If there was no ESS Signed Cert attribute and pades is true, then add one
        if (!addedSignedAttrs && pades) {
            newSigAttrSet.add(new DERSequence(getSignedCertAttr(digestAlgo, cert, includeIssuerSerial)));
        }

        //Der encode the new signed attributes set
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DEROutputStream dout = new DEROutputStream(bout);
        dout.writeObject(new DERSet(newSigAttrSet));
        byte[] newSigAttr = bout.toByteArray();
        dout.close();
        bout.close();
        return newSigAttr;
    }

    public static byte[] updateOrAddCMSAlgoProtectionAndSigTIme(byte[] signedAttrBytes, SupportedSigAlgoritm sigAlog) throws IOException, NoSuchAlgorithmException, CertificateException {
        ASN1Set inAttrSet = ASN1Set.getInstance(new ASN1InputStream(signedAttrBytes).readObject());
        ASN1EncodableVector newSigAttrSet = new ASN1EncodableVector();

        boolean addedCMSAlgoProt = false;
        for (int i = 0; i < inAttrSet.size(); i++) {
            Attribute attr = Attribute.getInstance(inAttrSet.getObjectAt(i));

            if (isCMSAlgoProtAttr(attr)) {
                //replace the existing signed signer cert attribute with a new one.
                newSigAttrSet.add(new DERSequence(getCMSAlgoProtAttr(sigAlog)));
                addedCMSAlgoProt = true;
                continue;
            }
            if (isSigTimeAttr(attr)) {
                newSigAttrSet.add(new DERSequence(getSigningTimeAtt()));
                continue;
            }
            newSigAttrSet.add(attr);

        }

        //If there was no ESS Signed Cert attribute, then add one
        if (!addedCMSAlgoProt) {
            newSigAttrSet.add(new DERSequence(getCMSAlgoProtAttr(sigAlog)));
        }

        //Der encode the new signed attributes set
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DEROutputStream dout = new DEROutputStream(bout);
        dout.writeObject(new DERSet(newSigAttrSet));
        byte[] newSigAttr = bout.toByteArray();
        dout.close();
        bout.close();
        return newSigAttr;
    }

    public static byte[] removeSignedAttr(byte[] signedAttrBytes, ASN1ObjectIdentifier[] attrOid) throws IOException, NoSuchAlgorithmException, CertificateException {
        ASN1Set inAttrSet = ASN1Set.getInstance(new ASN1InputStream(signedAttrBytes).readObject());
        ASN1EncodableVector newSigAttrSet = new ASN1EncodableVector();
        List<ASN1ObjectIdentifier> attrOidList = Arrays.asList(attrOid);

        for (int i = 0; i < inAttrSet.size(); i++) {
            Attribute attr = Attribute.getInstance(inAttrSet.getObjectAt(i));

            if (!attrOidList.contains(attr.getAttrType())) {
                newSigAttrSet.add(attr);
            }
        }

        //Der encode the new signed attributes set
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DEROutputStream dout = new DEROutputStream(bout);
        dout.writeObject(new DERSet(newSigAttrSet));
        byte[] newSigAttr = bout.toByteArray();
        dout.close();
        bout.close();
        return newSigAttr;
    }

    private static boolean isEssSigCertAttr(Attribute attr) {
        String attrOid = attr.getAttrType().getId();
        return attrOid.equalsIgnoreCase(PdfObjectIds.ID_AA_SIGNING_CERTIFICATE_V1) || attrOid.equalsIgnoreCase(PdfObjectIds.ID_AA_SIGNING_CERTIFICATE_V2);
    }

    private static boolean isCMSAlgoProtAttr(Attribute attr) {
        String attrOid = attr.getAttrType().getId();
        return attrOid.equalsIgnoreCase(PdfObjectIds.ID_AA_CMS_ALGORITHM_PROTECTION);
    }

    private static boolean isSigTimeAttr(Attribute attr) {
        String attrOid = attr.getAttrType().getId();
        return attrOid.equalsIgnoreCase(PdfObjectIds.ID_SIGNING_TIME);
    }

    public static ASN1EncodableVector getSignedCertAttr(DigestAlgorithm digestAlgo, Certificate cert, boolean includeIssuerSerial) throws NoSuchAlgorithmException, CertificateEncodingException, IOException, CertificateException {
        X509Certificate certificate = getCert(cert);
        final X500Name issuerX500Name = new X509CertificateHolder(certificate.getEncoded()).getIssuer();
        final GeneralName generalName = new GeneralName(issuerX500Name);
        final GeneralNames generalNames = new GeneralNames(generalName);
        final BigInteger serialNumber = certificate.getSerialNumber();
        final IssuerSerial issuerSerial = new IssuerSerial(generalNames, serialNumber);

        ASN1EncodableVector signedCert = new ASN1EncodableVector();

        boolean essSigCertV2;
        ASN1ObjectIdentifier signedCertOid;
        switch (digestAlgo) {
            case SHA1:
                signedCertOid = new ASN1ObjectIdentifier(PdfObjectIds.ID_AA_SIGNING_CERTIFICATE_V1);
                essSigCertV2 = false;
                break;
            default:
                signedCertOid = new ASN1ObjectIdentifier(PdfObjectIds.ID_AA_SIGNING_CERTIFICATE_V2);
                essSigCertV2 = true;
        }

        MessageDigest md = MessageDigest.getInstance(digestAlgo.getName());
        md.update(certificate.getEncoded());
        byte[] certHash = md.digest();
        signedCert.add(signedCertOid);

        ASN1EncodableVector attrValSet = new ASN1EncodableVector();
        ASN1EncodableVector signingCertObjSeq = new ASN1EncodableVector();
        ASN1EncodableVector essCertV2Seq = new ASN1EncodableVector();
        ASN1EncodableVector certSeq = new ASN1EncodableVector();
        ASN1EncodableVector algoSeq = new ASN1EncodableVector();
        algoSeq.add(new ASN1ObjectIdentifier(digestAlgo.getOid()));
        algoSeq.add(DERNull.INSTANCE);
        if (essSigCertV2) {
            certSeq.add(new DERSequence(algoSeq));
        }
        //Add cert hash
        certSeq.add(new DEROctetString(certHash));
        if (includeIssuerSerial) {
            certSeq.add(issuerSerial);
        }

        //Finalize assembly
        essCertV2Seq.add(new DERSequence(certSeq));
        signingCertObjSeq.add(new DERSequence(essCertV2Seq));
        attrValSet.add(new DERSequence(signingCertObjSeq));
        signedCert.add(new DERSet(attrValSet));

        return signedCert;
    }

    public static X509Certificate getCert(Certificate inCert) throws IOException, CertificateException {
        X509Certificate cert = null;
        ByteArrayInputStream certIs = new ByteArrayInputStream(inCert.getEncoded());

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(certIs);

        } finally {
            certIs.close();
        }
        return cert;
    }

    public static byte[] getRSAPkcs1DigestInfo(DigestAlgorithm digestAlgo, byte[] hashValue) throws IOException {
        ASN1EncodableVector digestInfoSeq = new ASN1EncodableVector();
        AlgorithmIdentifier algoId = digestAlgo.getAlgorithmIdentifier();
        digestInfoSeq.add(algoId);
        digestInfoSeq.add(new DEROctetString(hashValue));

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        DEROutputStream dout = new DEROutputStream(bout);
        dout.writeObject((new DERSequence(digestInfoSeq)));
        byte[] digestInfoBytes = bout.toByteArray();
        dout.close();
        bout.close();

        return digestInfoBytes;
    }

    private static ASN1EncodableVector getCMSAlgoProtAttr(SupportedSigAlgoritm sigAlgo) {
        ASN1EncodableVector algoProtSeq = new ASN1EncodableVector();
        ASN1EncodableVector attrSet = new ASN1EncodableVector();
        ASN1EncodableVector algoIdSeq = new ASN1EncodableVector();

        algoIdSeq.add(sigAlgo.getDigestAlgo().getAlgorithmIdentifier());

        switch (sigAlgo.getPkAlgoType()) {
            case EC:
            case RSA:
                algoIdSeq.add(new DERTaggedObject(false, 1, sigAlgo.getAlgorithmIdentifier()));
                break;
//                algoIdSeq.add(new DERTaggedObject(false, 1, new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"), DERNull.INSTANCE)));
//                break;
            case Unknown:
                break;
            default:
                throw new AssertionError(sigAlgo.getPkAlgoType().name());
        }

        attrSet.add(new DERSequence(algoIdSeq));
        algoProtSeq.add(new ASN1ObjectIdentifier(PdfObjectIds.ID_AA_CMS_ALGORITHM_PROTECTION));
        algoProtSeq.add(new DERSet(attrSet));

        return algoProtSeq;

    }

    private static ASN1EncodableVector getSigningTimeAtt() {
        ASN1EncodableVector sigTimeSeq = new ASN1EncodableVector();
        ASN1EncodableVector attrSet = new ASN1EncodableVector();
        attrSet.add(new ASN1UTCTime(new Date()));

        sigTimeSeq.add(new ASN1ObjectIdentifier(PdfObjectIds.ID_SIGNING_TIME));
        sigTimeSeq.add(new DERSet(attrSet));

        return sigTimeSeq;
    }

}
