/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.instances;

import java.util.List;

/**
 *
 * @author stefan
 */
public class InstanceMetadata {
    private LangStrings displayName;
    private LangStrings description;
    private List<MetadataLogo> logoList;
    private List<String> entityCategoryList;
    private LangStrings orgName;
    private LangStrings orgDisplayName;
    private LangStrings orgURL;
    private String supContactGivenName;
    private String supContactSurName;
    private String supContactEmail;
    private String supContactTel;
    private String techContactGivenName;
    private String techContactSurName;
    private String techContactEmail;
    private String techContactTel;

    public InstanceMetadata() {
    }

    public LangStrings getDisplayName() {
        return displayName;
    }

    public void setDisplayName(LangStrings displayName) {
        this.displayName = displayName;
    }

    public LangStrings getDescription() {
        return description;
    }

    public void setDescription(LangStrings description) {
        this.description = description;
    }

    public LangStrings getOrgName() {
        return orgName;
    }

    public void setOrgName(LangStrings orgName) {
        this.orgName = orgName;
    }

    public LangStrings getOrgDisplayName() {
        return orgDisplayName;
    }

    public void setOrgDisplayName(LangStrings orgDisplayName) {
        this.orgDisplayName = orgDisplayName;
    }

    public LangStrings getOrgURL() {
        return orgURL;
    }

    public void setOrgURL(LangStrings orgURL) {
        this.orgURL = orgURL;
    }

    public List<MetadataLogo> getLogoList() {
        return logoList;
    }

    public void setLogoList(List<MetadataLogo> logoList) {
        this.logoList = logoList;
    }

    public List<String> getEntityCategoryList() {
        return entityCategoryList;
    }

    public void setEntityCategoryList(List<String> entityCategoryList) {
        this.entityCategoryList = entityCategoryList;
    }

    public String getSupContactGivenName() {
        return supContactGivenName;
    }

    public void setSupContactGivenName(String supContactGivenName) {
        this.supContactGivenName = supContactGivenName;
    }

    public String getSupContactSurName() {
        return supContactSurName;
    }

    public void setSupContactSurName(String supContactSurName) {
        this.supContactSurName = supContactSurName;
    }

    public String getSupContactEmail() {
        return supContactEmail;
    }

    public void setSupContactEmail(String supContactEmail) {
        this.supContactEmail = supContactEmail;
    }

    public String getTechContactGivenName() {
        return techContactGivenName;
    }

    public void setTechContactGivenName(String techContactGivenName) {
        this.techContactGivenName = techContactGivenName;
    }

    public String getTechContactSurName() {
        return techContactSurName;
    }

    public void setTechContactSurName(String techContactSurName) {
        this.techContactSurName = techContactSurName;
    }

    public String getTechContactEmail() {
        return techContactEmail;
    }

    public void setTechContactEmail(String techContactEmail) {
        this.techContactEmail = techContactEmail;
    }

    public String getSupContactTel() {
        return supContactTel;
    }

    public void setSupContactTel(String supContactTel) {
        this.supContactTel = supContactTel;
    }

    public String getTechContactTel() {
        return techContactTel;
    }

    public void setTechContactTel(String techContactTel) {
        this.techContactTel = techContactTel;
    }
    
}
