package com.pingidentity.adapters.htmlform.idrecovery.servlet;

import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter;
import com.pingidentity.adapters.htmlform.idrecovery.common.RecoverUsernameConfiguration;
import com.pingidentity.adapters.htmlform.idrecovery.handler.RecoverUsernameHandler;
import com.pingidentity.adapters.htmlform.idrecovery.model.RecoverUsernameForm;
import com.pingidentity.adapters.htmlform.idrecovery.type.RecoverUsernameResult;
import com.pingidentity.adapters.htmlform.pwdreset.servlet.AbstractPasswordResetServlet;
import com.pingidentity.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.pingidentity.adapters.htmlform.pwdreset.util.UrlUtil;
import com.pingidentity.captcha.CaptchaServerSideValidator;
import com.pingidentity.captcha.CaptchaValidationError;
import com.pingidentity.common.util.CrossSiteRequestForgeryHelper;
import com.pingidentity.common.util.EscapeUtils;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.sourceid.oauth20.handlers.HandlerUtil;
import org.sourceid.saml20.domain.CaptchaSettings;
import org.sourceid.saml20.domain.LocalSettings;
import org.sourceid.saml20.domain.mgmt.CaptchaManager;
import org.sourceid.saml20.domain.mgmt.InvalidRedirectValidationException;
import org.sourceid.saml20.domain.mgmt.LocalSettingsManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.TargetResourceValidationMgr;
import org.sourceid.websso.profiles.ProcessRuntimeException;
import org.sourceid.websso.servlet.reqparam.InvalidRequestParameterException;

public class RecoverUsernameServlet extends AbstractPasswordResetServlet
{
  private static Log logger = LogFactory.getLog(RecoverUsernameServlet.class);
  
  private static final String RECOVER_USERNAME_REQUEST = "USERNAME_RECOVER";
  
  private static TargetResourceValidationMgr redirectValidationMgr = (TargetResourceValidationMgr)org.sourceid.config.GlobalRegistry.getService(TargetResourceValidationMgr.class);
  





  public void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    if (logger.isDebugEnabled()) { logger.debug("GET Request to /ext/idrecovery/Recover");
    }
    clearState(request, response);
    Map<String, Object> defaultParams = getDefaultParams(request);
    
    String cSRFToken = CrossSiteRequestForgeryHelper.generateAndStoreCSRFToken(request, response);
    defaultParams.put("cSRFToken", cSRFToken);
    
    String targetResource = StringUtils.defaultIfEmpty(request.getParameter("TargetResource"), getTargetResource(request));
    if ((targetResource != null) && (!targetResource.isEmpty()) && (!"$returnInfo".equals(targetResource)))
    {
      defaultParams.put("returnInfo", EscapeUtils.escape(targetResource));
    }
    
    String adapterId = request.getParameter("AdapterId") != null ? request.getParameter("AdapterId") : request.getParameter("pf.adapterId");
    
    this.sessionUtil.add("adapterId", adapterId, request, response);
    
    render(request, response, adapterId, defaultParams);
  }
  
  public void doPost(HttpServletRequest request, HttpServletResponse response)
  {
    if (logger.isDebugEnabled()) { logger.debug("POST Request to /ext/idrecovery/Recover");
    }
    String usernameRecovery = request.getParameter("pf.usernamerecovery");
    if ((StringUtils.isNotBlank(usernameRecovery)) && ("clicked".equalsIgnoreCase(usernameRecovery)))
    {
      doGet(request, response);
      return;
    }
    
    UrlUtil urlUtil = new UrlUtil(request);
    PwdResetAuditLogger.init("USERNAME_RECOVER", request, response);
    Map<String, Object> defaultParams = getDefaultParams(request);
    
    String cSRFToken = CrossSiteRequestForgeryHelper.validateCSRFToken(request, response);
    if ((cSRFToken == null) && (!validStage("stage1End", request, response)))
    {
      PwdResetAuditLogger.logFailure("Invalid state (unauthorized method)");
      redirect(response, urlUtil.buildErrorUrl("invalidState"));
      return;
    }
    defaultParams.put("cSRFToken", cSRFToken);
    
    RecoverUsernameForm form = null;
    RecoverUsernameResult validationResult = null;
    RecoverUsernameConfiguration configuration = getRecoverUsernameConfiguration(request, response);
    
    try
    {
      form = parseRequest(request, response);
      
      if ((form.isSubmit()) && (configuration.isEnableCaptcha()))
      {
        CaptchaServerSideValidator captchaServerSideValidator = new CaptchaServerSideValidator(request, MgmtFactory.getCaptchaManager().getCaptchaSettings().getSecretKey());
        boolean isValid = captchaServerSideValidator.validateRecaptcha();
        
        if (!isValid)
        {
          logger.debug("Login failed: reCAPTCHA validation failure.");
          if (captchaServerSideValidator.hasErrors())
          {
            for (CaptchaValidationError captchaValidationError : captchaServerSideValidator.getErrors())
            {
              logger.error("Login failed due to: " + captchaValidationError.getErrorId() + " - " + captchaValidationError.getMessage());
            }
          }
          
          validationResult = RecoverUsernameResult.Error;
        }
      }
      
      if (validationResult == null)
      {
        PwdResetAuditLogger.setUserName(form.getEmail());
        RecoverUsernameHandler handler = new RecoverUsernameHandler(configuration);
        validationResult = handler.validateEmailAddress(form, request, response);
      }
      
      setStage("stage1End", request, response);

    }
    catch (InvalidRequestParameterException e)
    {
      logger.error(e.getMessage());
      validationResult = RecoverUsernameResult.Error;
    }
    catch (JSONException e)
    {
      logger.error(e.getMessage());
      validationResult = RecoverUsernameResult.Error;
    }
    catch (IOException e)
    {
      logger.error(e.getMessage());
      validationResult = RecoverUsernameResult.Error;
    }
    

    auditRequestResult(validationResult);
    

    switch (validationResult)
    {



    case UserNotFound: 
    case MailNotVerified: 
    case Error: 
    case EmailSent: 
      renderInfo(request, response, defaultParams, form);
      break;
    case Cancel: 
      clearState(request, response);
      redirect(response, urlUtil.buildCancelUrl(form.getTargetResource(), "username.recovery.template.error.cancel"));
      break;
    case NoEmailAddress: 
      defaultParams.put("errorMessageKey", "noEmail");
      if (form.getTargetResource() != null)
      {
        defaultParams.put("returnInfo", EscapeUtils.escape(form.getTargetResource()));
      }
      render(request, response, configuration.getAdapterId(), defaultParams);
    }
    
  }
  
  private RecoverUsernameForm parseRequest(HttpServletRequest request, HttpServletResponse response)
    throws InvalidRequestParameterException
  {
    RecoverUsernameForm recoverUsernameForm = new RecoverUsernameForm(this.sessionUtil, request, response);
    
    String email = request.getParameter("email");
    String rawTargetResource = request.getParameter("savedReferrer");
    
    if (StringUtils.isNotEmpty(email))
    {
      recoverUsernameForm.setEmail(email);
    }
    
    if (StringUtils.isNotEmpty(rawTargetResource))
    {
      try
      {
        boolean hasUpnavigation = HandlerUtil.pathContainsUpNavigation(new java.net.URI(rawTargetResource));
        
        boolean setTargetResource = true;
        if ((!fromHtmlFormAdapter(rawTargetResource)) && (redirectValidationMgr.isEnableValidationTargetResourceSLOAndOther()))
        {
          try
          {
            redirectValidationMgr.validateTargetResourceSloAndOther(rawTargetResource, null);
          }
          catch (InvalidRedirectValidationException ex)
          {
            logger.warn(String.format("Ignoring request parameter TargetResource '%s' as it does not pass TargetResource validation.", new Object[] { rawTargetResource }));
            setTargetResource = false;
          }
        }
        
        if (hasUpnavigation)
        {
          String message = "The value '" + rawTargetResource + "' for the request parameter '" + "savedReferrer" + "' contains up-navigation and is disallowed.";
          throw new InvalidRequestParameterException(message);
        }
        
        if (setTargetResource)
        {
          recoverUsernameForm.setTargetResource(rawTargetResource);
        }
      }
      catch (URISyntaxException e)
      {
        String message = "The request parameter 'savedReferrer' has an invalid URL value '" + rawTargetResource + "'.";
        throw new InvalidRequestParameterException(message);
      }
    }
    

    if (request.getParameter("Resume") != null)
    {
      boolean isClicked = request.getParameter("Resume").equals("clicked");
      recoverUsernameForm.setSubmit(isClicked);
    }
    
    return recoverUsernameForm;
  }
  
  private void render(HttpServletRequest request, HttpServletResponse response, String adapterId, Map<String, Object> params)
  {
    RecoverUsernameConfiguration configuration = getRecoverUsernameConfiguration(request, response);
    String baseUrl = MgmtFactory.getLocalSettingsManager().getLocalSettings().getBaseUrl();
    try
    {
      params.put("email", "email");
      params.put("returnInfoField", "savedReferrer");
      params.put("ok", "Resume");
      params.put("cancel", "Cancel");
      params.put("passwordReset", "pf.passwordreset");
      params.put("supportsPasswordRecovery", Boolean.valueOf(configuration.isEnablePasswordRecovery()));
      params.put("forgotPasswordUrl", HtmlFormIdpAuthnAdapter.getForgetPasswordUrl(baseUrl, adapterId, (String)params.get("returnInfo")));
      params.put("captchaEnabled", Boolean.valueOf(configuration.isEnableCaptcha()));
      if (configuration.isEnableCaptcha())
      {
        params.put("siteKey", MgmtFactory.getCaptchaManager().getCaptchaSettings().getSiteKey());
      }
      

      if (!params.containsKey("savedEmail"))
      {
        params.put("savedEmail", "");
      }
      

      setStage("stage1Start", request, response);
      
      TemplateRendererUtil.render(request, response, configuration.getUsernameRecoveryTemplate(), params);
    }
    catch (Exception ex)
    {
      logger.error("Error on Request to /ext/idrecovery/Recover", ex);
      throw new ProcessRuntimeException(ex);
    }
  }
  
  private void renderInfo(HttpServletRequest request, HttpServletResponse response, Map<String, Object> params, RecoverUsernameForm form)
  {
    RecoverUsernameConfiguration configuration = getRecoverUsernameConfiguration(request, response);
    
    params.put("returnInfoField", "savedReferrer");
    params.put("cancel", "Cancel");
    if (StringUtils.isNotBlank(form.getTargetResource()))
    {
      params.put("successContinue", "true");
    }
    

    setStage("stage1End", request, response);
    try
    {
      TemplateRendererUtil.render(request, response, configuration.getUsernameRecoveryInfoTemplate(), params);
    }
    catch (Exception ex)
    {
      logger.error("Error on Request to /ext/idrecovery/Recover", ex);
      throw new ProcessRuntimeException(ex);
    }
  }
  





  private static void auditRequestResult(RecoverUsernameResult validationResult)
  {
    switch (validationResult)
    {
    case Cancel: 
    case NoEmailAddress: 
      break;
    
    case Error: 
      PwdResetAuditLogger.logFailure("System error (see server log)");
      break;
    case UserNotFound: 
      PwdResetAuditLogger.logFailure("User not found");
      break;
    case MailNotVerified: 
      PwdResetAuditLogger.logFailure("User found but email address not verified.");
      break;
    case EmailSent: 
      PwdResetAuditLogger.log();
      break;
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\idrecovery\servlet\RecoverUsernameServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */