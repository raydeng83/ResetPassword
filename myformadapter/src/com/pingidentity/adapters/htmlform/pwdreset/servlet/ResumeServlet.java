package com.pingidentity.adapters.htmlform.pwdreset.servlet;

import com.pingidentity.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.handler.ResumeHandler;
import com.pingidentity.adapters.htmlform.pwdreset.model.ResumeForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.ResumeResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import com.pingidentity.adapters.htmlform.pwdreset.util.UrlUtil;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.token.PFInternalTokenGenerator;
import org.sourceid.token.jwt.JwtTokenGeneratorImpl;
import org.sourceid.token.jwt.PFInternalTokenException;
import org.sourceid.token.jwt.PFResetPasswordtoJwtTranslator;
import org.sourceid.websso.servlet.reqparam.InvalidRequestParameterException;




public class ResumeServlet
  extends AbstractPasswordResetServlet
{
  private static Log logger = LogFactory.getLog(ResumeServlet.class);
  




  public void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    PwdResetAuditLogger.init("PWD_RESET_REQUEST_RESPONSE", request, response);
    logger.debug("GET Request to /ext/pwdreset/Resume");
    
    UrlUtil urlUtil = new UrlUtil(request);
    ResumeForm form = new ResumeForm(this.sessionUtil, request, response);
    PFInternalTokenGenerator tokenGenerator = new JwtTokenGeneratorImpl(new PFResetPasswordtoJwtTranslator());
    

    AttributeValue adapterId = null;
    

    Map<String, AttributeValue> attrs = null;
    try
    {
      attrs = tokenGenerator.decrypt(form.getReferenceId());
      adapterId = (AttributeValue)attrs.get("adapterId");
    }
    catch (PFInternalTokenException e)
    {
      if (1 == e.getError())
      {
        handleExpiredLink(response, urlUtil, "Code not validated within time tolerance");
        return;
      }
      

      throw new InvalidRequestParameterException(e.getMessage());
    }
    

    if (adapterId == null)
    {
      PwdResetAuditLogger.logFailure("Invalid OTL (no data for ref ID)");
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidLink"));
      return;
    }
    
    if (!validResetType(adapterId.getValue()))
    {
      PwdResetAuditLogger.logFailure("Invalid state (unauthorized method)");
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
      return;
    }
    
    Object usernameSession = this.sessionUtil.get("prUsername", request, response);
    Object adapterIdSession = this.sessionUtil.get("adapterId", request, response);
    Object referrerSession = this.sessionUtil.get("prReferrer", request, response);
    

    clearState(request, response);
    
    try
    {
      PwdResetAuditLogger.setUserName(form.getUsername());
      PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(adapterId.getValue());
      ResumeHandler handler = new ResumeHandler(configuration);
      ResumeResult validationResult = handler.validateLink(form, request, response, attrs);
      

      form.setUsername((String)this.sessionUtil.get("prUsername", request, response));
      PwdResetAuditLogger.setUserName(form.getUsername());
      
      setStage("stage2End", request, response);
      
      switch (validationResult) {
      case Error: 
        PwdResetAuditLogger.logFailure("OTL unexpected error (see server log)");
        redirect(response, urlUtil.buildErrorUrl(""));
        break;
      case Success: 
        setStage("stage2Authenticated", request, response);
        String url = getSuccessActionUrl(request, response, urlUtil, configuration, form);
        if ((referrerSession != null) && (form.getUsername().equals(usernameSession)) && (adapterId.getValue().equals(adapterIdSession)))
        {
          this.sessionUtil.add("prSuccessTarget", referrerSession, request, response);
        }
        redirect(response, url);
        break;
      case LinkExpired: 
        handleExpiredLink(response, urlUtil, "The OTL has already been used for a successful password reset and cannot be re-used.");
        break;
      case InvalidLink: 
        PwdResetAuditLogger.logFailure("Invalid OTL (no data for ref ID)");
        redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidLink"));
        break;
      case NoReferenceId: 
        PwdResetAuditLogger.logFailure("Invalid OTL (ref ID not found)");
        redirect(response, urlUtil.buildErrorUrl("forgot-password-error.noCodeInRequest"));
      }
    }
    catch (Exception ex) {
      PwdResetAuditLogger.logFailure("OTL unexpected error (see server log)");
      logger.error("Error occurred on /ext/pwdreset/Resume", ex);
      try {
        redirect(response, urlUtil.buildErrorUrl(""));
      }
      catch (Exception localException1) {}
    }
  }
  
  private void handleExpiredLink(HttpServletResponse response, UrlUtil urlUtil, String errorMessage) {
    PwdResetAuditLogger.logFailure("OTL expired");
    logger.error(errorMessage);
    redirect(response, urlUtil.buildErrorUrl("forgot-password-error.linkExpired"));
  }
  


  private boolean validResetType(String adapterId)
  {
    PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(adapterId);
    return "OTL".equals(configuration.getResetType());
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\servlet\ResumeServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */