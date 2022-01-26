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
package com.aaasec.sigserv.sigserver;

import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.Constants;
import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.metadata.MetaData;
import com.aaasec.sigserv.cscommon.URLEncoder;
import com.aaasec.sigserv.cscommon.enums.Enums;
import com.aaasec.sigserv.csdaemon.ContextParameters;
import com.aaasec.sigserv.cssigapp.SigRequestHandler;
import com.aaasec.sigserv.cssigapp.data.DbSignTask;
import com.aaasec.sigserv.cssigapp.data.ReqResult;
import com.aaasec.sigserv.cssigapp.data.SigConfig;
import com.aaasec.sigserv.cssigapp.data.SignAcceptPageInfo;
import com.aaasec.sigserv.cssigapp.db.SignTaskTable;
import com.aaasec.sigserv.cssigapp.utils.CertificateUtils;
import com.aaasec.sigserv.cssigapp.utils.NamedKeyStore;
import com.aaasec.sigserv.sigserver.auth.AuthRequest;
import com.google.gson.Gson;
import iaik.x509.X509Certificate;
import se.idsec.audit.signservice.AuditLogger;

import java.io.IOException;
import java.util.logging.Logger;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet for handling sign requests
 */
public class RequestHandlerServlet extends HttpServlet implements Constants {

    private static final Logger LOG = Logger.getLogger(RequestHandlerServlet.class.getName());
    private boolean devmode;
    private String dataLocation;
    private String sigServletUrl;
    private SigRequestHandler serverFront;
    private SigConfig conf;
    private SignTaskTable signDb;
    private Gson gson = new Gson();
    private MetaData metaData;

    @Override
    public void init(ServletConfig config) throws ServletException {
        //Security.insertProviderAt(new iaik.security.provider.IAIK(), Security.getProviders().length);
        dataLocation = ContextParameters.getDataLocation();
        conf = ContextParameters.getConf();
        devmode = conf.isDevmode();
        serverFront = new SigRequestHandler(dataLocation);
        String sigTaskDir = FileOps.getfileNameString(dataLocation, "sigTasks");
        String sigTaskDbFile = FileOps.getfileNameString(sigTaskDir, "sigTasks.db");
        signDb = new SignTaskTable(sigTaskDbFile);
        //metaData = MetadataFactory.getMetadata("/opt/local/var/run/shibboleth/eid2-test-1.0.xml", 60);

        metaData = ContextParameters.getMetadata();
    }

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        LOG.fine("Received request on sign request URL");

        request.setCharacterEncoding("UTF-8");
        metaData = ContextParameters.getMetadata();

        String sigRequest = request.getParameter("EidSignRequest");
        String binding = request.getParameter("Binding");
        String nonce = request.getParameter("RelayState");
        String action = request.getParameter("action");
        String id = request.getParameter("id");
        String parameter = request.getParameter("parameter");
        action = (action == null) ? "" : action;

        if (sigRequest != null) {
            LOG.fine("Received request with sign request input parameter");
            response.setContentType("text/html;charset=UTF-8");
            byte[] decoded = null;
            try {
                decoded = Base64Coder.decode(sigRequest.trim());
            } catch (Exception ex) {
            }
            ReqResult signRequestStatus = serverFront.handeSignRequest(decoded);

            //New code starts here
            if (signRequestStatus.code.equals(Enums.ResponseCodeMajor.Success.getCode())) {
                LOG.fine("Sucessul parse of sign request. Looking for sign task reccord in DB");
                DbSignTask task = signDb.getDbRecord(signRequestStatus.id);
                if (task== null){
                    LOG.warning("Null signtask from signtask DB");
                }
                if (devmode) {
                    LOG.warning("Received request while service is in in dev mode");
                    task.getPageInfo().sigReuestRedirectUrl = "../devIdp.jsp?action=sign&id=" + signRequestStatus.id;
                    signDb.addOrReplaceRecord(task);
                    response.sendRedirect("devIdp.jsp?action=sign&id=" + signRequestStatus.id);
                    return;
                }
                LOG.fine("Attempting to build authentication request");
                AuthRequest authReq = new AuthRequest(task, signRequestStatus, decoded,signRequestStatus.signServiceEntityId);
                boolean authnReqSuccess = authReq.prepareAuthRequest();
                if (!authnReqSuccess && signRequestStatus.spUrl != null) {
                    LOG.warning("Failed to generate authentication request");
                    //Generate error sign response if spUrl is known
                    ReqResult reqResult = new ReqResult(Enums.ResponseCodeMajor.BadRequest, nonce, signRequestStatus.spUrl, authReq.getErrorMessage());
                    NamedKeyStore instanceKs = serverFront.getInstanceKeystore(decoded);
                    AuditLogger.logSignResult(decoded, "Failed to generate authentication request to IdP", false);
                    SigRequestHandler.setErrorResponse(reqResult, null, instanceKs);
                    response.getWriter().write(reqResult.errorResponse);
                    response.getWriter().close();
                    return;
                }
                if (authReq.getSadRequestId()!=null){
                    LOG.fine("Adding SAD request to signTask DB");
                    task.getPageInfo().sadRequestId=authReq.getSadRequestId();
                    signDb.addOrReplaceRecord(task);
                }
                LOG.fine("Sending Auth request to IdP");
                authReq.sendRequest(request, response);
                return;
            }

            // If request was in error
            if (signRequestStatus.errorResponse.length() > 0
                    && signRequestStatus.spUrl.length() > 0) {
                response.getWriter().write(signRequestStatus.errorResponse);
                response.getWriter().close();
                return;
            }
            if (signRequestStatus.code != null) {
                response.setContentType("text");
                StringBuilder b = new StringBuilder();
                if (signRequestStatus.code.length()>0){
                    b.append(signRequestStatus.code);
                    b.append(" - ");
                }
                if (signRequestStatus.message!=null && signRequestStatus.message.length()>0){
                    b.append(signRequestStatus.message);
                } else {
                    b.append("General error");
                }
                response.getWriter().write(b.toString());
                response.getWriter().close();

            }
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            response.getWriter().write("");
            response.getWriter().close();
            return;
        }

        if (action.equals("status")) {
            LOG.fine("Received request on status request URL");
            response.setContentType("application/json;charset=UTF-8");
            try {
                DbSignTask task = signDb.getDbRecord(id);
                SignAcceptPageInfo pageInfo = task.getPageInfo();
                response.getWriter().write(gson.toJson(pageInfo));
                return;
            } catch (Exception ex) {
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                response.getWriter().write("");
                return;
            }
        }

        if (action.equals("signmessage")) {
            response.setContentType("text/html;charset=UTF-8");
            try {
                DbSignTask task = signDb.getDbRecord(id);
                String message = new String(task.getSignMessage(), "UTF-8");
                response.getWriter().write(message);
                return;
            } catch (Exception ex) {
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                response.getWriter().write("");
                return;
            }
        }

        if (action.equals("certprint")) {
            try {
                byte[] certBytes = Base64Coder.decode(URLEncoder.unmaskB64String(parameter));
                X509Certificate cert = CertificateUtils.getCertificate(certBytes);
                response.getWriter().write(cert.toString(true));
                return;
            } catch (Exception ex) {
                String exs = ex.getMessage();
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                response.getWriter().write("");
                return;
            }
        }
        LOG.fine("No valid request parameters received. No content response");

        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        response.getWriter().write("");
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

    private String prepareSigResponse(String sigRequest, String binding, String nonce) {
        StringBuilder b = new StringBuilder();
        b.append("<html>");
        b.append("<head>");
        b.append("<title>Servlet SigServlet</title>");
        b.append("</head>");
        b.append("<body>");
        b.append("<h1>SigServlet response</h1>");
        b.append("<b>Binding:</b> ").append(binding).append("<br />");
        b.append("<b>Nonce:</b> ").append(nonce).append("<br />").append("<br />");
        b.append("<b>Data:</b>");
        b.append("<xmp>").append(sigRequest).append("</xmp>");
        b.append("</body>");
        b.append("</html>");
        return b.toString();
    }
}
