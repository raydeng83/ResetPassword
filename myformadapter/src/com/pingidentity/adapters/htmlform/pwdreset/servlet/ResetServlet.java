package com.pingidentity.adapters.htmlform.pwdreset.servlet;

import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapterUtils;
import com.pingidentity.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.handler.ResetHandler;
import com.pingidentity.adapters.htmlform.pwdreset.model.ResetForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.ResetResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import com.pingidentity.adapters.htmlform.pwdreset.util.UrlUtil;
import com.pingidentity.common.util.CrossSiteRequestForgeryHelper;
import com.pingidentity.sdk.password.PasswordResetException;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.websso.profiles.ProcessRuntimeException;




public class ResetServlet
  extends AbstractPasswordResetServlet
{
  private static Log logger = LogFactory.getLog(ResetServlet.class);
  
  public void doGet(HttpServletRequest request, HttpServletResponse response) {
    logger.debug("GET Request to /ext/pwdreset/Reset");
    
    UrlUtil urlUtil = new UrlUtil(request);
    
    Map<String, Object> defaultParams = getDefaultParams(request);
    
    if (!validStage("stage2Authenticated", request, response)) {
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
      return;
    }
    

    this.sessionUtil.remove("prCount", request, response);
    
    String cSRFToken = CrossSiteRequestForgeryHelper.getCSRFToken(request, response);
    defaultParams.put("cSRFToken", cSRFToken);
    
    render(request, response, defaultParams);
  }
  
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    PwdResetAuditLogger.init("PWD_RESET", request, response);
    logger.debug("POST Request to /ext/pwdreset/Reset");
    
    UrlUtil urlUtil = new UrlUtil(request);
    
    Map<String, Object> defaultParams = getDefaultParams(request);
    
    String cSRFToken = validateCSRFToken(request, response);
    if ((cSRFToken == null) || (!validStage("stage3Start", request, response))) {
      PwdResetAuditLogger.logFailure("Invalid state (unauthorized method)");
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
      return;
    }
    defaultParams.put("cSRFToken", cSRFToken);
    
    ResetForm form = new ResetForm(this.sessionUtil, request, response);
    PwdResetAuditLogger.setUserName(form.getUsername());
    PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
    ResetHandler handler = new ResetHandler(configuration);
    
    String exceptionMessage = null;
    ResetResult validationResult;
    try {
      validationResult = handler.resetPassword(form, request, response);
    }
    catch (PasswordResetException e) {
      ResetResult validationResult;
      validationResult = ResetResult.PasswordConstraintViolation;
      exceptionMessage = e.getMessage();
    }
    
    setStage("stage3End", request, response);
    
    switch (validationResult) {
    case NoNewPassword: 
      PwdResetAuditLogger.logFailure("Password not provided");
      defaultParams.put("errorMessageKey", "forgot-password-change.noNewPassword");
      render(request, response, defaultParams);
      break;
    case NoConfirmPassword: 
      PwdResetAuditLogger.logFailure("Confirm password not provided");
      defaultParams.put("errorMessageKey", "forgot-password-change.noConfirmPassword");
      render(request, response, defaultParams);
      break;
    case PasswordConstraintViolation: 
      PwdResetAuditLogger.logFailure("Password policy constraint violation");
      defaultParams.put("errorMessageKey", StringUtils.isEmpty(exceptionMessage) ? "forgot-password-change.doesNotMatchPasswordConstraint" : exceptionMessage);
      
      render(request, response, defaultParams);
      break;
    case Expired: 
      PwdResetAuditLogger.logFailure("Reset token expired");
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.codeExpired"));
      break;
    case Success: 
      PwdResetAuditLogger.log();
      if ((form.getTargetResource() != null) && (form.getTargetResource().startsWith("http"))) {
        this.sessionUtil.add("prSuccessTarget", form.getTargetResource(), request, response);
      }
      if ((configuration.isEnableRememberMyUsername()) && (this.sessionUtil.get("prEnableRememberUsername", request, response) != null))
      {
        String cookieName = configuration.getRememberMyUsernameCookieName();
        int age = configuration.getRememberMyUsernameCookieLifetime();
        HtmlFormIdpAuthnAdapterUtils.addCookie(cookieName, form.getUsername(), age, response);
      }
      redirect(response, urlUtil.buildSuccessUrl("forgot-password-success.passwordChangeSuccessful"));
      break;
    case Error: 
      PwdResetAuditLogger.logFailure("Unexpected error setting password (see server log)");
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.passwordChangeFailed"));
      break;
    case PasswordMismatch: 
      PwdResetAuditLogger.logFailure("Password mismatch");
      defaultParams.put("errorMessageKey", "forgot-password-change.passwordMismatch");
      render(request, response, defaultParams);
      break;
    
    case Cancel: 
      logger.debug("Reset canceled");
      clearState(request, response);
      redirect(response, urlUtil.buildCancelUrl(form.getTargetResource()));
      break;
    default: 
      PwdResetAuditLogger.logFailure("Unexpected error with resetting the password (see server log)");
      redirect(response, urlUtil.buildErrorUrl(""));
    }
  }
  
  private void render(HttpServletRequest request, HttpServletResponse response, Map<String, Object> params)
  {
    params.put("url", request.getContextPath() + "/");
    params.put("password1", "Password1");
    params.put("password2", "Password2");
    params.put("ok", "Reset");
    params.put("cancel", "Cancel");
    

    setStage("stage3Start", request, response);
    
    try
    {
      PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
      TemplateRendererUtil.render(request, response, configuration.getChangeTemplate(), params);
    }
    catch (Exception ex)
    {
      logger.error("Error on Request to /ext/pwdreset/Reset", ex);
      throw new ProcessRuntimeException(ex);
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\servlet\ResetServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */