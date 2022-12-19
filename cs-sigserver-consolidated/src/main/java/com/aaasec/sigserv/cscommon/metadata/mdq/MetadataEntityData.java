package com.aaasec.sigserv.cscommon.metadata.mdq;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.aaasec.sigserv.cscommon.metadata.EntityType;

import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;

/**
 * Metadata entity data
 */
public class MetadataEntityData {

  public MetadataEntityData() {
  }

  private String entityId;
  private Instant lastDownload;
  private Instant expires;
  private List<String> certificateList;
  private String encCertificate;
  private Map<String, String> nameMap;
  private EntityType entityType;
  private Map<String, String> ssoMap;
  private List<String> idpSupportedLoAList;
  private EntityDescriptorType entityDescriptor;

  public String getEntityId() {
    return entityId;
  }

  public void setEntityId(String entityId) {
    this.entityId = entityId;
  }

  public Instant getLastDownload() {
    return lastDownload;
  }

  public void setLastDownload(Instant lastDownload) {
    this.lastDownload = lastDownload;
  }

  public Instant getExpires() {
    return expires;
  }

  public void setExpires(Instant expires) {
    this.expires = expires;
  }

  public List<String> getCertificateList() {
    return certificateList;
  }

  public void setCertificateList(List<String> certificateList) {
    this.certificateList = certificateList;
  }

  public String getEncCertificate() {
    return encCertificate;
  }

  public void setEncCertificate(String encCertificate) {
    this.encCertificate = encCertificate;
  }

  public Map<String, String> getNameMap() {
    return nameMap;
  }

  public void setNameMap(Map<String, String> nameMap) {
    this.nameMap = nameMap;
  }

  public EntityType getEntityType() {
    return entityType;
  }

  public void setEntityType(EntityType entityType) {
    this.entityType = entityType;
  }

  public Map<String, String> getSsoMap() {
    return ssoMap;
  }

  public void setSsoMap(Map<String, String> ssoMap) {
    this.ssoMap = ssoMap;
  }

  public List<String> getIdpSupportedLoAList() {
    return idpSupportedLoAList;
  }

  public void setIdpSupportedLoAList(List<String> idpSupportedLoAList) {
    this.idpSupportedLoAList = idpSupportedLoAList;
  }

  public EntityDescriptorType getEntityDescriptor() {
    return entityDescriptor;
  }

  public void setEntityDescriptor(EntityDescriptorType entityDescriptor) {
    this.entityDescriptor = entityDescriptor;
  }
}
