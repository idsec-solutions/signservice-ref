package se.idsec.audit.signservice;

import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import com.aaasec.sigserv.cssigapp.SignatureCreationHandler;
import com.aaasec.sigserv.cssigapp.instances.InstanceConfig;
import se.elegnamnden.id.csig.x11.dssExt.ns.SignRequestExtensionType;
import x0CoreSchema.oasisNamesTcDss1.ResultDocument;
import x0CoreSchema.oasisNamesTcDss1.SignRequestDocument;

import java.io.ByteArrayInputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AuditLogger {
  private static final Logger auditLog = Logger.getLogger(AuditLogger.class.getName());

  public static void log(String message, String... params){
    log(message, false, params);
  }

  public static synchronized void log(String message, boolean warning, String... params){

    message = message == null ? "NULL log message" : message;

    if (params!=null){
      for (String param : params){
        message = message.replaceFirst("\\{}", param);
      }
    }

    if (warning){
      auditLog.warning(message);
    } else {
      auditLog.info(message);
    }
  }

  public static void logSignResult(SignatureCreationHandler.RequestAndResponse reqRes, String sigInstanceName) {
    try {
      SignRequestExtensionType signRequestExtension = reqRes.getRequest().getOptionalInputs().getSignRequestExtension();
      String requesterId = signRequestExtension.getSignRequester().getStringValue();
      String idpEntityId = signRequestExtension.getIdentityProvider().getStringValue();

      ResultDocument.Result result = reqRes.getResponse().getResult();
      String resultMajor = result.getResultMajor();

      boolean success = resultMajor.equalsIgnoreCase(Enums.ResponseCodeMajor.Success.getCode());
      String message = success ? "Signature creation SUCCESS" : "Signature creation FAILED";

      logSignResult(success, requesterId, idpEntityId, sigInstanceName, message);
    } catch (Exception ex){
      auditLog.log(Level.SEVERE, "Critical error while attempting to audit log result",ex);
    }
  }

  /**
   * Audit logging the result of a sign process
   * @param SignRequestBytes bytes of the sign request
   * @param success true if the sign process was successful
   */
  public static void logSignResult(byte[] SignRequestBytes, String message, boolean success) {
    try {
      SignRequestExtensionType signRequestExtension = SignRequestDocument.Factory.parse(new ByteArrayInputStream(SignRequestBytes))
        .getSignRequest()
        .getOptionalInputs()
        .getSignRequestExtension();
      String requesterId = signRequestExtension.getSignRequester().getStringValue();
      String idpEntityId = signRequestExtension.getIdentityProvider().getStringValue();
      InstanceConfig instanceConf = ContextParameters.getInstanceConf();
      String sigInstanceName = instanceConf.getEntityIdInstanceName(signRequestExtension.getSignService().getStringValue());
      logSignResult(success, requesterId, idpEntityId, sigInstanceName, message);

    } catch (Exception ex) {
      auditLog.log(Level.SEVERE, "Critical error while attempting to audit log result",ex);
    }
  }

  public static void logSignResult(boolean success, String requesterId, String idpEntityId, String sigInstanceName, String message) {
    log(
      "{} - ServiceProvider: {}, IdentityProvider: {}, Instance: {}",
      !success,
      message,
      requesterId,
      idpEntityId,
      sigInstanceName
    );
  }
}
