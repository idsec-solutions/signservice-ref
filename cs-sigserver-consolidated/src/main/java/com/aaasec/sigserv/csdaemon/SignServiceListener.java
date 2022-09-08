package com.aaasec.sigserv.csdaemon;

import com.aaasec.sigserv.cscommon.config.ConfigFactory;
import com.aaasec.sigserv.cscommon.metadata.MetadataFactory;
import com.aaasec.sigserv.cssigapp.data.SigConfig;
import com.aaasec.sigserv.cssigapp.instances.InstanceConfig;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import com.aaasec.sigserv.cssigapp.sap.SAPHandler;
import com.aaasec.sigserv.xmlsign.SigComXMLSign;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.security.SecurityConfiguration;

/**
 * Web application lifecycle listener.
 *
 * @author stefan
 */
public class SignServiceListener implements ServletContextListener {

    private static final Logger LOG = Logger.getLogger(SignServiceListener.class.getName());
    private static final String DATA_LOCATION_ENV = "SIGNSERVICE_DATALOCATION";
    private static String servletPath = "/cs-sigserver";
    private CaDaemon daemon = null;
    //private static String envDataLocation;

    static {
        Security.insertProviderAt(new iaik.security.provider.IAIK(), 2);
        //envDataLocation = System.getenv("SIG_DATA_LOCATION");
    }

    public static String getServletPath() {
        return servletPath;
    }

    public static void setServletPath(String servletPath) {
        SignServiceListener.servletPath = servletPath;
    }

    @Override
    public void contextInitialized(ServletContextEvent sce) {

        LOG.info("Initializing Signservice....");

        ServletContext servletContext = sce.getServletContext();
        String contextPath = servletContext.getContextPath();
        contextPath = (contextPath == null) ? "null" : contextPath;
        if (contextPath.equals(servletPath)) {
            //Init Daemon
            ServletContext sc = sce.getServletContext();


            // Get datalocation from Environment Variable or from web.xml
            String envDataLocation = System.getenv(DATA_LOCATION_ENV);
            String dataLocation = envDataLocation == null ? sc.getInitParameter("DataLocation") : envDataLocation;

            dataLocation = envDataLocation == null ? dataLocation : envDataLocation;
            String verboseLogging = sc.getInitParameter("VerboseLogging");
            String preventDuplicateUserTasks = sc.getInitParameter("PreventDuplicateUserTasks");

            ContextParameters.setDataLocation(dataLocation);
            ContextParameters.setVerboseLogging(verboseLogging.equalsIgnoreCase("true"));
            ContextParameters.setPreventDuplicateUserTasks(preventDuplicateUserTasks.equalsIgnoreCase("true"));
            ContextParameters.setSapHandler(new SAPHandler());

            getConfig();
            getMetadata();

            try {
                initOpenSaml2();
            } catch (Exception ex) {
                Logger.getLogger(SignServiceListener.class.getName()).log(Level.SEVERE, null, ex);
            }

            if (daemon == null && dataLocation != null) {
                daemon = new CaDaemon();
                daemon.invokeDaemon();
            }
        }
    }

    private static void initOpenSaml2() throws Exception {
        DefaultBootstrap.bootstrap();

        SecurityConfiguration config = Configuration.getGlobalSecurityConfiguration();
        if (!(config instanceof BasicSecurityConfiguration)) {
            return;
        }
        BasicSecurityConfiguration secConfig = (BasicSecurityConfiguration) config;
        secConfig.setSignatureReferenceDigestMethod(SigComXMLSign.SHA256);
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        if (daemon != null) {
            daemon.stopDaemon();
            daemon = null;
        }
    }

    private void getConfig() {
        String dataLocation = ContextParameters.getDataLocation();
        ConfigFactory<SigConfig> confFact = new ConfigFactory<SigConfig>(dataLocation, new SigConfig());
        SigConfig conf = confFact.getConfData();
        ContextParameters.setConf(conf);
        InstanceConfig instanceConf = new InstanceConfig();
        instanceConf.reloadConf();
        ContextParameters.setInstanceConf(instanceConf);        
    }

    private void getMetadata() {
        SigConfig conf = ContextParameters.getConf();
        MetadataFactory metadataFactory = new MetadataFactory();
        metadataFactory.setLocation(conf.getMetadataLocation());
        metadataFactory.setCertLocation(ContextParameters.getCompleteMetadataCertLocation());
        metadataFactory.setRecachetimeMinutes(conf.getMetadataRefreshMinutes());

        ContextParameters.setMetadataFactory(metadataFactory);
    }
}
