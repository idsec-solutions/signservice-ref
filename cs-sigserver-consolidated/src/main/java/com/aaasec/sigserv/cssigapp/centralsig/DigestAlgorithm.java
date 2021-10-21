/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.centralsig;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;
import javax.xml.crypto.dsig.DigestMethod;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * @author stefan
 */
public enum DigestAlgorithm {

    SHA1("SHA-1", "1.3.14.3.2.26", DigestMethod.SHA1, 20),
    SHA224("SHA-224", "2.16.840.1.101.3.4.2.4", "http://www.w3.org/2001/04/xmldsig-more#sha224", 28),
    SHA256("SHA-256", "2.16.840.1.101.3.4.2.1", DigestMethod.SHA256, 32),
    SHA384("SHA-384", NISTObjectIdentifiers.id_sha384.getId(), "http://www.w3.org/2001/04/xmldsig-more#sha384", 48),
    SHA512("SHA-512", "2.16.840.1.101.3.4.2.3", DigestMethod.SHA512, 64);

    private String name;
    private String oid;
    private String xmlId;
    private int hLen;

    private DigestAlgorithm(String name, String oid, String xmlId, int hLen) {
        this.name = name;
        this.oid = oid;
        this.xmlId = xmlId;
        this.hLen = hLen;
    }

    /**
     * Return the algorithm corresponding to the name
     * 
     * @param algoName
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static DigestAlgorithm getByName(String algoName) throws NoSuchAlgorithmException {
        if ("SHA-1".equals(algoName) || "SHA1".equals(algoName)) {
            return SHA1;
        }
        if ("SHA-256".equals(algoName)) {
            return SHA256;
        }
        if ("SHA-512".equals(algoName)) {
            return SHA512;
        }
        throw new NoSuchAlgorithmException("unsupported algo: " + algoName);
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the oid
     */
    public String getOid() {
        return oid;
    }

    /**
     * @return the xmlId
     */
    public String getXmlId() {
        return xmlId;
    }

    /**
     * @return Lengh of hash value
     */
    public int gethLen() {
        return hLen;
    }

    /**
     * Gets the ASN.1 algorithm identifier structure corresponding to this digest algorithm
     * 
     * @return the AlgorithmIdentifier
     */
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        /*
         * The recommendation (cf. RFC 3380 section 2.1) is to omit the parameter for SHA-1, but some implementations
         * still expect a NULL there. Therefore we always include a NULL parameter even with SHA-1, despite the
         * recommendation, because the RFC states that implementations SHOULD support it as well anyway
         */
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(this.getOid()), DERNull.INSTANCE);
    }
    
    public static DigestAlgorithm getDigestAlgoFromOid(String oid){
        for (DigestAlgorithm hashAlgo:values()){
            if (oid.equalsIgnoreCase(hashAlgo.getOid())){
                return hashAlgo;
            }
        }
        return null;
    }

    public static DigestAlgorithm getDigestAlgoFromURI(String uriId){
        Optional<DigestAlgorithm> digestAlgorithmOptional = Arrays.stream(values())
          .filter(digestAlgorithm -> digestAlgorithm.getXmlId().equals(uriId))
          .findFirst();
        return digestAlgorithmOptional.isPresent() ? digestAlgorithmOptional.get() : null;
    }

}

