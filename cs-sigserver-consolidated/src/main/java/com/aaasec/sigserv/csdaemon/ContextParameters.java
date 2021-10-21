/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.csdaemon;

import com.aaasec.sigserv.cscommon.metadata.MetaData;
import com.aaasec.sigserv.cscommon.metadata.MetadataFactory;
import com.aaasec.sigserv.cssigapp.data.SigConfig;
import com.aaasec.sigserv.cssigapp.instances.InstanceConfig;
import com.aaasec.sigserv.cssigapp.sap.SAPHandler;

/**
 *
 * @author stefan
 */
public class ContextParameters {

    private static String dataLocation;
    private static boolean verboseLogging;
    private static boolean preventDuplicateUserTasks;
    private static SigConfig conf;
    private static InstanceConfig instanceConf;
    private static SAPHandler sapHandler;
    private static MetadataFactory metadataFactory;
    
    
    private ContextParameters() {
    }

    public static String getPublicationUrl(){
        return conf.getSigServiceBaseUrl() + "/publish";
    }

    public static String getSigRequestAndAssertionConsumerUrl(){
        return conf.getSigServiceBaseUrl() + "/sign";
    }

    public static String getCompleteCaFileSorageLocation(){
        if (conf.getCaFileStorageLocation(). startsWith("/")){
            return conf.getCaFileStorageLocation();
        }
        return dataLocation + "/" + conf.getCaFileStorageLocation();
    }

    public static String getCompleteMetadataCertLocation(){
        if (conf.getMetadataCertLocation(). startsWith("/")){
            return conf.getMetadataCertLocation();
        }
        return dataLocation + "/" + conf.getMetadataCertLocation();
    }

    public static String getDataLocation() {
        return dataLocation;
    }

    public static void setDataLocation(String dataLocation) {
        ContextParameters.dataLocation = dataLocation;
    }

    public static boolean isVerboseLogging() {
        return verboseLogging;
    }

    public static void setVerboseLogging(boolean verboseLogging) {
        ContextParameters.verboseLogging = verboseLogging;
    }

    public static boolean isPreventDuplicateUserTasks() {
        return preventDuplicateUserTasks;
    }

    public static void setPreventDuplicateUserTasks(boolean preventDuplicateUserTasks) {
        ContextParameters.preventDuplicateUserTasks = preventDuplicateUserTasks;
    }

    public static MetaData getMetadata() {
        return metadataFactory.getMetadata();
    }

    public static SigConfig getConf() {
        return conf;
    }

    public static void setConf(SigConfig conf) {
        ContextParameters.conf = conf;
    }

    public static InstanceConfig getInstanceConf() {
        return instanceConf;
    }

    public static void setInstanceConf(InstanceConfig instanceConf) {
        ContextParameters.instanceConf = instanceConf;
    }

    public static SAPHandler getSapHandler() {
        return sapHandler;
    }

    public static void setSapHandler(SAPHandler sapHandler) {
        ContextParameters.sapHandler = sapHandler;
    }

    public static MetadataFactory getMetadataFactory() {
        return metadataFactory;
    }

    public static void setMetadataFactory(MetadataFactory metadataFactory) {
        ContextParameters.metadataFactory = metadataFactory;
    }
}
