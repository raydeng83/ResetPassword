package com.efx.pingfed.adapters.htmlform.pwdreset.servlet;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.efx.pingfed.adapters.htmlform.pwdreset.handler.PingIDHandler;
import com.efx.pingfed.adapters.htmlform.pwdreset.model.PingIDForm;
import com.efx.pingfed.adapters.htmlform.pwdreset.type.PingIDResult;
import com.efx.pingfed.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.efx.pingfed.adapters.htmlform.pwdreset.util.UrlUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class PingIDServlet
  extends AbstractPasswordResetServlet
{
  private static Log logger = LogFactory.getLog(PingIDServlet.class);
  




  public void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    PwdResetAuditLogger.init("PWD_RESET_REQUEST_RESPONSE", request, response);
    logger.debug("GET Request to /ext/pwdreset/PingID");
    
    UrlUtil urlUtil = new UrlUtil(request);
    
    PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
    
    if ((!validStage("stage1End", request, response)) || (!validResetType(configuration.getResetType()))) {
      PwdResetAuditLogger.logFailure("Invalid state (unauthorized method)");
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
      return;
    }
    
    PingIDForm form = new PingIDForm(this.sessionUtil, request, response);
    PwdResetAuditLogger.setUserName(form.getUsername());
    PingIDHandler handler = new PingIDHandler(configuration);
    
    String pcvId = (String)this.sessionUtil.get("pcvId", request, response);
    
    String pingIdUsername = handler.getPingUserId(form.getUsername(), pcvId);
    
    setStage("stage2Start", request, response);
    

    if ((pingIdUsername != null) && (handler.isActiveForAuthentication(pingIdUsername)))
    {


      try
      {

        String returnUrl = form.getRootPath() + urlUtil.buildPingAuthReturnUrl();
        handler.sendAuthRequest(pingIdUsername, returnUrl, request, response);
      }
      catch (Exception e)
      {
        PwdResetAuditLogger.logFailure("PingID request failed (see server log)");
        String pingIDAuthenticatorPath = configuration.getPingIdAuthenticatorUrl() + "/auth";
        
        logger.error("Error posting request to: " + pingIDAuthenticatorPath, e);
        redirect(response, urlUtil.buildErrorUrl("forgot-password-error.authFailed"));
      }
      
    }
    else
    {
      PwdResetAuditLogger.logFailure("PingID user not enrolled");
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.notEnrolled"));
    }
  }
  
  public void doPost(HttpServletRequest request, HttpServletResponse response)
  {
    PwdResetAuditLogger.init("PWD_RESET_REQUEST_RESPONSE", request, response);
    logger.debug("POST Request to /ext/pwdreset/PingID");
    
    UrlUtil urlUtil = new UrlUtil(request);
    
    PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
    
    if ((!validStage("stage2Start", request, response)) || (!validResetType(configuration.getResetType()))) {
      PwdResetAuditLogger.logFailure("Invalid state (unauthorized method)");
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
      return;
    }
    
    PingIDForm form = new PingIDForm(this.sessionUtil, request, response);
    PwdResetAuditLogger.setUserName(form.getUsername());
    PingIDHandler handler = new PingIDHandler(configuration);
    

    PingIDResult result = handler.validatePingID(form, request, response);
    
    setStage("stage2End", request, response);
    String url;
    String url;
    String url;
    String url; switch (result)
    {
    case Success: 
      setStage("stage2Authenticated", request, response);
      url = getSuccessActionUrl(request, response, urlUtil, configuration, form);
      break;
    case Canceled: 
      PwdResetAuditLogger.logFailure("PingID authentication canceled");
      String url = urlUtil.buildCancelUrl(form.getTargetResource());
      clearState(request, response);
      redirect(response, url);
      break;
    case Expired: 
      PwdResetAuditLogger.logFailure("PingID request expired");
      url = urlUtil.buildErrorUrl("forgot-password-error.authFailed");
      break;
    case AuthFailed: 
      PwdResetAuditLogger.logFailure("PingID authentication failed");
      url = urlUtil.buildErrorUrl("forgot-password-error.authFailed");
      break;
    default: 
      PwdResetAuditLogger.logFailure("PingID unexpected error (see server log)");
      url = urlUtil.buildErrorUrl("");
    }
    redirect(response, url);
  }
  


  private boolean validResetType(String resetType)
  {
    return "PingID".equals(resetType);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\servlet\PingIDServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */