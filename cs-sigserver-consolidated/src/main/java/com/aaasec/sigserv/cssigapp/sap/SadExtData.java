/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.sap;

/**
 *
 * @author stefan
 */
public class SadExtData {

    String ver,irt,attr,loa,reqid;
    int docs;

    public SadExtData() {
    }

    public SadExtData(String ver, String irt, String attr, String loa, String reqid, int docs) {
        this.ver = ver;
        this.irt = irt;
        this.attr = attr;
        this.loa = loa;
        this.reqid = reqid;
        this.docs = docs;
    }

    public String getVer() {
        return ver;
    }

    public void setVer(String ver) {
        this.ver = ver;
    }

    public String getIrt() {
        return irt;
    }

    public void setIrt(String irt) {
        this.irt = irt;
    }

    public String getAttr() {
        return attr;
    }

    public void setAttr(String attr) {
        this.attr = attr;
    }

    public String getLoa() {
        return loa;
    }

    public void setLoa(String loa) {
        this.loa = loa;
    }

    public String getReqid() {
        return reqid;
    }

    public void setReqid(String reqid) {
        this.reqid = reqid;
    }

    public int getDocs() {
        return docs;
    }

    public void setDocs(int docs) {
        this.docs = docs;
    }

}
