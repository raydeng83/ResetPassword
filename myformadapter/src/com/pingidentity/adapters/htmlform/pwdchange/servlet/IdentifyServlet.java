package com.pingidentity.adapters.htmlform.pwdchange.servlet;

import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapterUtils;
import com.pingidentity.adapters.htmlform.pwdchange.common.ChangePasswordSessionState;
import com.pingidentity.adapters.htmlform.pwdchange.common.PasswordChangeConfiguration;
import com.pingidentity.adapters.htmlform.pwdchange.handler.ChangePasswordHandler;
import com.pingidentity.adapters.htmlform.pwdchange.handler.IdentifyHandler;
import com.pingidentity.adapters.htmlform.pwdchange.model.IdentifyForm;
import com.pingidentity.adapters.htmlform.pwdchange.render.ChangePasswordWithForm;
import com.pingidentity.adapters.htmlform.pwdchange.type.ChangePasswordResult;
import com.pingidentity.adapters.htmlform.pwdchange.type.IdentifyResult;
import com.pingidentity.adapters.htmlform.pwdreset.servlet.AbstractPasswordResetServlet;
import com.pingidentity.captcha.CaptchaServerSideValidator;
import com.pingidentity.captcha.CaptchaValidationError;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Logger;
import org.json.JSONException;
import org.sourceid.config.GlobalRegistry;
import org.sourceid.oauth20.protocol.Parameters;
import org.sourceid.saml20.adapter.state.TransactionalStateSupport;
import org.sourceid.saml20.domain.CaptchaSettings;
import org.sourceid.saml20.domain.LocalSettings;
import org.sourceid.saml20.domain.mgmt.CaptchaManager;
import org.sourceid.saml20.domain.mgmt.InvalidRedirectValidationException;
import org.sourceid.saml20.domain.mgmt.LocalSettingsManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.TargetResourceValidationMgr;
import org.sourceid.websso.servlet.reqparam.InvalidRequestParameterException;

public class IdentifyServlet extends AbstractPasswordResetServlet
{
  private static final String ERROR_USER_NAME_BLANK = "usernameBlankError";
  private static final String ERROR_OLD_PASSWORD_BLANK = "oldPasswordBlankError";
  private static final String ERROR_PASSWORD_MISMATCH = "newPasswordMismatchError";
  private static final String ERROR_NEW_PASSWORD_BLANK = "newPasswordBlankError";
  private static final String ERROR_OLD_AND_NEW_PASSWORD_MATCH = "oldAndNewPasswordMatchError";
  private static final String ERROR_ACCOUNT_LOCKED = "accountLockedError";
  private static final String ERROR_CAPTCHA = "captchaError";
  private static TargetResourceValidationMgr redirectValidationMgr = (TargetResourceValidationMgr)GlobalRegistry.getService(TargetResourceValidationMgr.class);
  
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
    throws IOException
  {
    ChangePasswordSessionState state = ChangePasswordSessionState.get(req, resp);
    
    state = validateAndSetTargetResource(req, state);
    
    if (StringUtils.isNotBlank(req.getParameter("AdapterId")))
    {
      state.setIdpAdapterId(req.getParameter("AdapterId"));
    }
    else if (StringUtils.isNotBlank(req.getParameter("adapterId")))
    {

      state.setIdpAdapterId(req.getParameter("adapterId"));
    }
    else
    {
      resp.sendError(404);
      return;
    }
    
    PasswordChangeConfiguration configuration = null;
    try
    {
      configuration = getPasswordChangeConfiguration(state);
    }
    catch (IllegalArgumentException ex)
    {
      this.logger.error(ex);
    }
    
    if ((configuration == null) || (!configuration.isAllowsChangePassword()))
    {
      resp.sendError(404);
      return;
    }
    
    state.setResumeId(null);
    state.save(req, resp);
    
    ChangePasswordWithForm changePasswordWithForm = new ChangePasswordWithForm();
    changePasswordWithForm.render(req, resp, null, state.getAuthnMessageKey());
  }
  

  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
    throws IOException
  {
    ChangePasswordSessionState state = ChangePasswordSessionState.get(req, resp);
    PasswordChangeConfiguration configuration = getPasswordChangeConfiguration(state);
    ChangePasswordWithForm changePasswordWithForm = new ChangePasswordWithForm();
    
    if (!configuration.isAllowsChangePassword())
    {
      resp.sendError(404);
      return;
    }
    
    if (StringUtils.isNotBlank(req.getParameter("pf.cancel")))
    {
      doCancel(req, resp, state, configuration);
    }
    else
    {
      IdentifyForm identifyForm = parseRequest(req);
      
      if (!identifyForm.isSubmit()) {
        this.logger.debug("Form was not submitted");
        doCancel(req, resp, state, configuration);
        return;
      }
      
      doCaptcha(req, configuration, identifyForm);
      
      if ((identifyForm.getErrorList() != null) && (!identifyForm.getErrorList().isEmpty()))
      {
        changePasswordWithForm.render(req, resp, identifyForm.getErrorList(), null);
        return;
      }
      
      IdentifyHandler identifyHandler = new IdentifyHandler(configuration);
      IdentifyResult identifyResult = identifyHandler.authenticateExistingCredentials(identifyForm, req, resp);
      
      switch (identifyResult)
      {
      case Authenticated: 
        ChangePasswordHandler changePasswordHandler = new ChangePasswordHandler(configuration);
        ChangePasswordResult changePasswordResult = changePasswordHandler.changePassword(identifyForm, req, resp);
        if (ChangePasswordResult.Success.equals(changePasswordResult))
        {
          if (configuration.isEnablePasswordExpiryNotification())
          {
            HtmlFormIdpAuthnAdapterUtils.addCookie("pf-hfa-exp-pwd", "", 0, resp);
          }
          
          String baseUrl = MgmtFactory.getLocalSettingsManager().getLocalSettings().getBaseUrl();
          String successEndpoint = baseUrl + "/ext/pwdchange/Success";
          
          String username = req.getParameter("pf.username");
          if ((state.isFromHtmlFormAdapter()) && (StringUtils.isNotBlank(username)))
          {
            successEndpoint = successEndpoint + "?pf.username=" + URLEncoder.encode(username, "UTF-8");
          }
          resp.sendRedirect(successEndpoint); }
        break;
      case NoUsername: 
        break;
      
      case AccountLocked: 
        changePasswordWithForm.render(req, resp, Arrays.asList(new String[] { "accountLockedError" }), null);
        break;
      case UserNotFound: 
        break;
      case Error: 
        break;
      case IncorrectCurrentPassword: 
        break;
      case PasswordExpired: 
        break;
      case Cancel: 
        break;
      }
      
    }
  }
  

  private void doCaptcha(HttpServletRequest req, PasswordChangeConfiguration configuration, IdentifyForm identifyForm)
    throws IOException
  {
    try
    {
      if ((identifyForm.isSubmit()) && (configuration.isCaptchaEnabledPasswordChange()))
      {
        CaptchaServerSideValidator captchaServerSideValidator = new CaptchaServerSideValidator(req, MgmtFactory.getCaptchaManager().getCaptchaSettings().getSecretKey());
        boolean isValid = captchaServerSideValidator.validateRecaptcha();
        
        if (!isValid)
        {
          this.logger.debug("Login failed: reCAPTCHA validation failure.");
          if (captchaServerSideValidator.hasErrors())
          {
            for (CaptchaValidationError captchaValidationError : captchaServerSideValidator.getErrors())
            {
              this.logger.error("Login failed due to: " + captchaValidationError.getErrorId() + " - " + captchaValidationError.getMessage());
            }
          }
          
          identifyForm.getErrorList().add("captchaError");
        }
      }
    }
    catch (JSONException e)
    {
      identifyForm.getErrorList().add("captchaError");
    }
  }
  

  private void doCancel(HttpServletRequest req, HttpServletResponse resp, ChangePasswordSessionState state, PasswordChangeConfiguration configuration)
    throws IOException
  {
    if (state.isFromHtmlFormAdapter())
    {
      TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(state.getTargetUrl());
      transactionalStateSupport.removeAttribute(state.getSessionKeyLoginContext(), req, resp);
    }
    
    state.delete(req, resp);
    if (StringUtils.isNotBlank(state.getTargetUrl()))
    {
      resp.sendRedirect(state.getTargetUrl());
    }
    else
    {
      Map<String, Object> params = new HashMap();
      
      params.put("headerMessage", "passwordChangedCancelHeaderMessage");
      params.put("authnMessageKey", null);
      params.put(Parameters.CLIENT_ID, state.getClientId());
      params.put("spAdapterId", state.getSpAdapterId());
      
      TemplateRendererUtil.render(req, resp, configuration.getChangePasswordMessageTemplateName(), params);
    }
  }
  
  private ChangePasswordSessionState validateAndSetTargetResource(HttpServletRequest req, ChangePasswordSessionState state)
  {
    String targetUrl = StringUtils.defaultIfEmpty(req.getParameter("TargetResource"), "");
    boolean setTargetUrl = (StringUtils.isBlank(state.getTargetUrl())) && (StringUtils.isNotBlank(targetUrl));
    if ((setTargetUrl) && (!state.isFromHtmlFormAdapter()) && (redirectValidationMgr.isEnableValidationTargetResourceSLOAndOther()))
    {
      try
      {
        redirectValidationMgr.validateTargetResourceSloAndOther(targetUrl, null);
      }
      catch (InvalidRedirectValidationException ex)
      {
        this.logger.error(String.format("Ignoring specified Target Resource '%s' as it does not pass redirect validation.", new Object[] { targetUrl }));
        setTargetUrl = false;
      }
    }
    
    if (setTargetUrl)
    {
      state.setTargetUrl(targetUrl);
    }
    
    return state;
  }
  
  private IdentifyForm parseRequest(HttpServletRequest req) throws InvalidRequestParameterException
  {
    IdentifyForm identifyForm = new IdentifyForm();
    String username = req.getParameter("pf.username");
    String password = req.getParameter("pf.pass");
    String newPassword1 = req.getParameter("pf.new.pass1");
    String newPassword2 = req.getParameter("pf.new.pass2");
    
    if (StringUtils.isBlank(username))
    {
      identifyForm.getErrorList().add("usernameBlankError");
    }
    if (StringUtils.isBlank(password))
    {
      identifyForm.getErrorList().add("oldPasswordBlankError");
    }
    if ((StringUtils.isBlank(newPassword1)) || (StringUtils.isBlank(newPassword2)))
    {
      identifyForm.getErrorList().add("newPasswordBlankError");
    }
    if (!StringUtils.equals(newPassword1, newPassword2))
    {
      identifyForm.getErrorList().add("newPasswordMismatchError");
    }
    if ((StringUtils.equals(password, newPassword1)) || (StringUtils.equals(password, newPassword2)))
    {
      identifyForm.getErrorList().add("oldAndNewPasswordMatchError");
    }
    
    identifyForm.setUsername(username);
    identifyForm.setCurrentPassword(password);
    identifyForm.setNewPassword(newPassword1);
    identifyForm.setConfirmNewPassword(newPassword2);
    if (req.getParameter("pf.ok") != null)
    {
      boolean isClicked = req.getParameter("pf.ok").equals("clicked");
      identifyForm.setSubmit(isClicked);
    }
    return identifyForm;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\servlet\IdentifyServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */