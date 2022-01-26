/*
 *  NFCSigning - Open source library for signing/validation of NDEF messages
 *  Copyright (C) 2009-2010 The NFCSigning Team
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */
package com.aaasec.sigserv.cssigapp.centralsig;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

/**
 * http://www.ipa.go.jp/security/rfc/RFC3279EN.html#223
 *
 * The Ecdsa-Sig-Value object.
 * <pre>
 *      Ecdsa-Sig-Value ::= SEQUENCE {
 * r INTEGER,
 * s INTEGER }
 * </pre>
 *
 * @author Markus KilÃ¥s
 */
public class EcdsaSigValue implements ASN1Encodable {

    private final BigInteger r;
    private final BigInteger s;

    public static EcdsaSigValue getInstance(
            ASN1TaggedObject obj,
            boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static EcdsaSigValue getInstance(Object obj) {
        if (obj instanceof EcdsaSigValue) {
            return (EcdsaSigValue) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new EcdsaSigValue((ASN1Sequence) obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public static EcdsaSigValue getInstance(byte[] concatenatedRS) {
        BigInteger[] rsVals = getRSfromConcatenatedBytes(concatenatedRS);
        try {
            return new EcdsaSigValue(rsVals[0], rsVals[1]);
        } catch (Exception ex) {
            return null;
        }
    }

    public static EcdsaSigValue getInstance(ASN1Sequence a1s) {
        return new EcdsaSigValue(a1s);
    }

    /**
     * Returns the ASN.1 sequence of DER encoded bytes holding a signature value
     * @param derEncodedAsn1Sequence The byte array of a DER encoded key value SEQUENCE
     * @return ECDSA key ASN.1 sequence object
     * @throws IOException 
     */
    public static ASN1Sequence getAsn1SequenceFromBytes(byte[] derEncodedAsn1Sequence) throws IOException {
        return ASN1Sequence.getInstance(new ASN1InputStream(derEncodedAsn1Sequence).readObject());
    }

    public EcdsaSigValue(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public EcdsaSigValue(ASN1Sequence obj) {
        Enumeration e = obj.getObjects();

        r = ASN1Integer.getInstance(e.nextElement()).getValue();
        s = ASN1Integer.getInstance(e.nextElement()).getValue();
    }

    public BigInteger getR() {
        return r;
    }

    public BigInteger getS() {
        return s;
    }

    private static BigInteger[] getRSfromConcatenatedBytes(byte[] concatenatedRS) {
        try {
            int rLen, sLen;
            int len = concatenatedRS.length;
            rLen = len / 2;
            sLen = rLen;

            byte[] rBytes = new byte[rLen];
            byte[] sBytes = new byte[sLen];

            System.arraycopy(concatenatedRS, 0, rBytes, 0, rLen);
            System.arraycopy(concatenatedRS, rLen, sBytes, 0, sLen);

            BigInteger[] srArray = new BigInteger[2];
            srArray[0] = getBigInt(rBytes);
            srArray[1] = getBigInt(sBytes);

            return srArray;

        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * @return the ASN.1 object of the signature value
     */
    public DERSequence toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));

        return new DERSequence(v);
    }

    /**
     * Gets the bytes that is to be carried in an OCTET STRING to form the CMS
     * signature value
     *
     * @return DER encoded bytes of the signature value ASN.1 SEQUENCE
     */
    public byte[] getDEREncodedSigValue() throws IOException {
        return toASN1Object().getEncoded("DER");
    }

    /**
     * Returns the concatenation of the bytes of r and s
     *
     * @return byte array representation of signature value
     */
    public byte[] toByteArray(int keyLen) {
        try {
            byte[] rBytes = trimByteArray(r.toByteArray(), keyLen);
            byte[] sBytes = trimByteArray(s.toByteArray(), keyLen);
            byte[] rsBytes = new byte[rBytes.length + sBytes.length];
            System.arraycopy(rBytes, 0, rsBytes, 0, rBytes.length);
            System.arraycopy(sBytes, 0, rsBytes, rBytes.length, sBytes.length);

            return rsBytes;
        } catch (Exception ex) {
            Logger.getLogger(EcdsaSigValue.class.getName()).warning(ex.getMessage());
        }
        return null;
    }

    private static byte[] trimByteArray(byte[] inpBytes, int keyLen) {
        int len = inpBytes.length;
        int tLen = keyLen / 8;
        if (len == tLen) {
            return inpBytes;
        }
        byte[] trimmed = new byte[tLen];

        if (len < tLen) {
            int padCnt = tLen - len;
            for (int i = 0; i < padCnt; i++) {
                trimmed[i] = 0x00;
                System.arraycopy(inpBytes, 0, trimmed, padCnt, len);
            }
        }

        if (len > tLen) {
            int truncCnt = len - tLen;
            System.arraycopy(inpBytes, truncCnt, trimmed, 0, len - truncCnt);
        }

        return trimmed;

    }

    private static BigInteger getBigInt(byte[] source) {
        byte[] padded = new byte[source.length + 1];
        padded[0] = 0x00;
        System.arraycopy(source, 0, padded, 1, source.length);
        return new BigInteger(padded);
    }

    public ASN1Primitive toASN1Primitive() {
        return toASN1Object();
    }
}
