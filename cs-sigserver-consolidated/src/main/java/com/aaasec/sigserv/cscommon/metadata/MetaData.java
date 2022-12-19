package com.aaasec.sigserv.cscommon.metadata;

import java.util.List;
import java.util.Map;

import x0Metadata.oasisNamesTcSAML2.EntityDescriptorType;

/**
 * Interface for accessing Metadata information
 */
public interface MetaData {
  boolean isEntityIdSupported(String entityId);

  boolean isInitialized();

  List<String> getCertificates(String entityId);

  Map<String, String> getNameMap(String entityId);

  String getEncCert(String entityId);

  String getName(String entityId, String prefLang);

  EntityType getEntityType(String entityId);
  Map<String, String> getSSOMap(String entityId);

  List<String> getIdpSupportedClassRefs(String entityId);

  EntityDescriptorType getEntityDescriptor(String entityId);
}
