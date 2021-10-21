/*
 * Copyright 2013 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *   Licensed under the EUPL, Version 1.1 or ñ as soon they will be approved by the 
 *   European Commission - subsequent versions of the EUPL (the "Licence");
 *   You may not use this work except in compliance with the Licence. 
 *   You may obtain a copy of the Licence at:
 * 
 *   http://joinup.ec.europa.eu/software/page/eupl 
 * 
 *   Unless required by applicable law or agreed to in writing, software distributed 
 *   under the Licence is distributed on an "AS IS" basis,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
 *   implied.
 *   See the Licence for the specific language governing permissions and limitations 
 *   under the Licence.
 */
package com.aaasec.sigserv.cssigapp.utils;

import com.aaasec.sigserv.cscommon.enums.Enums;
import iaik.asn1.ASN;
import iaik.asn1.ASN1;
import iaik.asn1.ASN1Object;
import iaik.asn1.CodingException;
import iaik.asn1.OCTET_STRING;
import iaik.asn1.ObjectID;
import iaik.asn1.SEQUENCE;
import iaik.asn1.UTCTime;
import iaik.x509.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SimpleTimeZone;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.apache.xml.security.signature.XMLSignature;

/**
 * ASN.1 utils.
 */
public class ASN1Util {

    private static final Logger LOG = Logger.getLogger(ASN1Util.class.getName());

    public static String getShortCertName(byte[] certBytes) {
        if (certBytes == null) {
            return "Invalid certificate";
        }
        X509Certificate iaikCert = KsCertFactory.getIaikCert(certBytes);
        return getShortCertName(iaikCert);
    }

    public static String getShortCertName(java.security.cert.X509Certificate cert) {
        try {
            return getShortCertName(cert.getEncoded());
        } catch (CertificateEncodingException ex) {
            return "Invalid certificate";
        }
    }

    public static String getShortCertName(X509Certificate iaikCert) {
        if (iaikCert == null) {
            return "Invalid certificate";
        }
        return getShortName(iaikCert.getSubjectX500Principal());
    }

    public static String getShortName(X500Principal dName) {
        Map<ObjectID, String> nameMap = getCertNameAttributes(dName);

        if (nameMap.containsKey(ObjectID.commonName)) {
            return nameMap.get(ObjectID.commonName);
        }
        StringBuilder b = new StringBuilder();
        if (nameMap.containsKey(ObjectID.surName)) {
            b.append(nameMap.get(ObjectID.surName));
        }
        if (nameMap.containsKey(ObjectID.givenName)) {
            b.append(" ").append(nameMap.get(ObjectID.givenName));
        }
        if (b.length() > 0) {
            return b.toString().trim();
        }
        if (nameMap.containsKey(ObjectID.organizationalUnit)) {
            b.append(nameMap.get(ObjectID.organizationalUnit));
        }
        if (nameMap.containsKey(ObjectID.organization)) {
            b.append(" ").append(nameMap.get(ObjectID.organization));
        }

        b.append(b.length() == 0 ? "No displayable name" : "");
        return b.toString().trim();
    }

    public static Map<ObjectID, String> getCertNameAttributes(X500Principal dName) {
        try {
            ASN1 subjectNameAsn1 = new ASN1(dName.getEncoded());
            int rdnCount = subjectNameAsn1.countComponents();
            //System.out.println("Number of RDNs: " + rdnCount);

            List<ASN1Object> attTaVs = new ArrayList<ASN1Object>();
            for (int i = 0; i < rdnCount; i++) {
                ASN1Object rdnSeq = subjectNameAsn1.getComponentAt(i);
                for (int j = 0; j < rdnSeq.countComponents(); j++) {
                    attTaVs.add(rdnSeq.getComponentAt(j));
                }
            }
            Map<ObjectID, String> nameMap = new HashMap<ObjectID, String>();
            for (ASN1Object attTaV : attTaVs) {
                ObjectID oid = new ObjectID((String) attTaV.getComponentAt(0).getValue());
                // Get name object
                Object no = attTaV.getComponentAt(1).getValue();
                String name = "**unknown value type**";
                if (no.getClass().equals(String.class)) {
                    name = (String) no;
                } else {
                    if (no.getClass().equals(ASN1Object.class)) {
                        name = ((ASN1Object) no).toString();
                    }
                }
                //System.out.println(oid.getNameAndID() + "\"" + name + "\"");
                nameMap.put(oid, name);
            }
            return nameMap;


        } catch (CodingException ex) {
            return null;
        }
    }

//    public static Set<Entry<ObjectID, String>> getCertNameAttributeSetOld(X509Certificate cert) {
//        try {
//            ASN1 subjectNameAsn1 = new ASN1(cert.getSubjectX500Principal().getEncoded());
//            int rdnCount = subjectNameAsn1.countComponents();
//            //System.out.println("Number of RDNs: " + rdnCount);
//
//            List<ASN1Object> attTaVs = new ArrayList<ASN1Object>();
//            for (int i = 0; i < rdnCount; i++) {
//                ASN1Object rdnSeq = subjectNameAsn1.getComponentAt(i);
//                for (int j = 0; j < rdnSeq.countComponents(); j++) {
//                    attTaVs.add(rdnSeq.getComponentAt(j));
//                }
//            }
//            Entry<ObjectID, String> entry;
//            Set<Entry<ObjectID, String>> set = new LinkedHashSet<Entry<ObjectID, String>>();
//            for (ASN1Object attTaV : attTaVs) {
//                ObjectID oid = new ObjectID((String) attTaV.getComponentAt(0).getValue());
//                // Get name object
//                Object no = attTaV.getComponentAt(1).getValue();
//                String name = "**unknown value type**";
//                if (no.getClass().equals(String.class)) {
//                    name = (String) no;
//                } else {
//                    if (no.getClass().equals(ASN1Object.class)) {
//                        name = ((ASN1Object) no).toString();
//                    }
//                }
//
//                //System.out.println(oid.getNameAndID() + "\"" + name + "\"");
//                entry = new SimpleEntry<ObjectID, String>(oid, name);
//                set.add(entry);
//            }
//            return set;
//
//
//        } catch (CodingException ex) {
//            return null;
//        }
//    }
    public static Set<Entry<ObjectID, String>> getCertNameAttributeSet(X509Certificate cert) {
        X500Principal distinguishedName = cert.getSubjectX500Principal();
        return getCertNameAttributeSet(distinguishedName);
    }

    public static Set<Entry<ObjectID, String>> getCertNameAttributeSet(X500Principal distinguishedName) {
        try {
            ASN1 subjectNameAsn1 = new ASN1(distinguishedName.getEncoded());
            int rdnCount = subjectNameAsn1.countComponents();
            List<ASN1Object> attTaVs = new ArrayList<ASN1Object>();

            for (int i = 0; i < rdnCount; i++) {
                ASN1Object rdnSeq = subjectNameAsn1.getComponentAt(i);
                for (int j = 0; j < rdnSeq.countComponents(); j++) {
                    attTaVs.add(rdnSeq.getComponentAt(j));
                }
            }
            List<OidNamePair> valuePairs = new ArrayList<OidNamePair>();
            for (ASN1Object attTaV : attTaVs) {
                getNameValue(attTaV, valuePairs);
            }
            Entry<ObjectID, String> entry;
            Set<Entry<ObjectID, String>> set = new LinkedHashSet<Entry<ObjectID, String>>();

            for (OidNamePair valuePair : valuePairs) {
                //System.out.println(oid.getNameAndID() + "\"" + name + "\"");
                entry = new SimpleEntry<ObjectID, String>(valuePair.oid, valuePair.name);
                set.add(entry);
            }
            return reverseOrder(set);

        } catch (CodingException ex) {
            return null;
        }
    }

    private static void getNameValue(ASN1Object attrTypeAndValue, List<OidNamePair> valuePairs) {

        try {
            ObjectID oid = new ObjectID((String) attrTypeAndValue.getComponentAt(0).getValue());
            // Get name object
            ASN1Object nameObject = attrTypeAndValue.getComponentAt(1);
            String name;
            if (oid.equals(ObjectID.postalAddress)) {
                getPostalAddressPairs(nameObject, valuePairs);
            } else {
                if (nameObject.isStringType()) {
                    name = (String) nameObject.getValue();
                    valuePairs.add(new OidNamePair(oid, name));
                }
            }
        } catch (Exception ex) {
            LOG.warning(ex.getMessage());
        }

    }

    private static void getPostalAddressPairs(ASN1Object postalAdrVal, List<OidNamePair> valuePairs) {
        if (postalAdrVal.getAsnType().equals(ASN.SEQUENCE)) {
            List<ASN1Object> nameList = getAsn1Objects(postalAdrVal);
            StringBuilder b = new StringBuilder();
            int i = 0;
            for (ASN1Object nameObj : nameList) {
                if (nameObj.isStringType()) {
                    b.append(nameObj.getValue());
                    if (++i < nameList.size()) {
                        b.append(", ");
                    }
                }
            }
            valuePairs.add(new OidNamePair(ObjectID.postalAddress, b.toString()));
        } else {
            valuePairs.add(new OidNamePair(ObjectID.postalAddress, "** content not decoded **"));
        }
    }

    private static List<ASN1Object> getAsn1Objects(ASN1Object asn1Obj) {
        List<ASN1Object> asn1ObjList = new ArrayList<ASN1Object>();
        try {
            for (int i = 0; i < asn1Obj.countComponents(); i++) {
                asn1ObjList.add(asn1Obj.getComponentAt(i));
            }
        } catch (CodingException ex) {
            LOG.warning(ex.getMessage());
        }
        return asn1ObjList;
    }

    private static Set<Entry<ObjectID, String>> reverseOrder(Set<Entry<ObjectID, String>> set) {
        Set<Entry<ObjectID, String>> reverse = new LinkedHashSet<Entry<ObjectID, String>>();
        Object[] o = new Object[set.size()];

        Iterator itr = set.iterator();
        int i = 0;
        while (itr.hasNext()) {
            o[i++] = itr.next();
        }
        for (i = o.length; i > 0; i--) {
            reverse.add((Entry<ObjectID, String>) o[i - 1]);
        }
        return reverse;
    }

    public static String getSigAlgofromTbsData(byte[] pkcs1Data) {
        try {
            ASN1 obj = new ASN1(pkcs1Data);
            ASN1Object a1o = obj.toASN1Object();
            if (a1o.countComponents() != 2) {
                return "";
            }
            //Get hash objectId
            ASN1Object oidObj = a1o.getComponentAt(0).getComponentAt(0);
            if (oidObj instanceof ObjectID) {
                ObjectID hashOid = (ObjectID) oidObj;
                if (Enums.digestNames.containsKey(hashOid.getID())) {
                    String algoName=Enums.digestNames.get(hashOid.getID());
                    
                    if (algoName.equals("SHA256")){
                        return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
                    }
                    if (algoName.equals("SHA1")){
                        return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1;
                    }
                }
            }

        } catch (CodingException ex) {
            return "";
        }
        return "";
    }
    
    public static byte[] getHashValueFromTbsData(byte[] pkcs1Data){
        try {
            ASN1 obj = new ASN1(pkcs1Data);
            ASN1Object a1o = obj.toASN1Object();
            if (a1o.countComponents() != 2) {
                return null;
            }
            //Get hash objectId
            ASN1Object hashObj = a1o.getComponentAt(1);
            if (hashObj instanceof OCTET_STRING) {                
                OCTET_STRING hash = (OCTET_STRING) hashObj;
                return hash.getWholeValue();
            }

        } catch (Exception ex) {
            return null;
        }
        return null;        
    }
    
    public static Date getCmsSigningTime(byte[] cmsSigAttr){
        try{
            ASN1Object a1o = new ASN1(cmsSigAttr).toASN1Object();
            int cnt = a1o.countComponents();
            for (int i=0;i<cnt;i++){
                ASN1Object seqObj = a1o.getComponentAt(i);
                if (seqObj instanceof SEQUENCE){
                   SEQUENCE  seq = (SEQUENCE) seqObj;
                   ObjectID attrOid = (ObjectID) seq.getComponentAt(0);
                   // if signing time
                   if (attrOid.equals(new ObjectID("1.2.840.113549.1.9.5"))){
                       UTCTime utcSigTime = (UTCTime) seq.getComponentAt(1).getComponentAt(0);
                        String value = (String) utcSigTime.getValue();
                        DateFormat df = new SimpleDateFormat("yyMMddHHmmss'Z'");
                        df.setTimeZone(new SimpleTimeZone(0,"Z"));
                        Date sigDate = (Date) df.parse(value);
                        return sigDate;
                   }
                }
                
            }                        
        }catch(Exception ex){            
        }
        return null;
    }
    

    static class OidNamePair {

        ObjectID oid;
        String name;

        public OidNamePair(ObjectID oid, String name) {
            this.oid = oid;
            this.name = name;
        }
    }
}