package com.efx.pingfed.adapters.htmlform.idp;

import com.efx.pingfed.adapters.htmlform.pwdchange.common.PasswordChangeConfiguration;
import com.efx.pingfed.adapters.htmlform.render.ChallengeWithForm;
import com.pingidentity.access.PasswordCredentialValidatorAccessor;
import com.pingidentity.adapters.htmlform.render.ChallengeWithForm.Builder;
import com.pingidentity.common.security.LockingService;
import com.pingidentity.common.util.CookieMonster;
import com.pingidentity.common.util.HTMLEncoder;
import com.pingidentity.sdk.password.*;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import com.pingidentity.sdk.template.TemplateRendererUtilException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.Util;
import org.sourceid.oauth20.protocol.Parameters;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.state.TransactionalStateSupport;
import org.sourceid.saml20.domain.AuthenticationResultEnum;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.impl.RadiusAdminUserException;
import org.sourceid.util.log.AttributeMap;
import org.sourceid.websso.AuditLogger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

public class AuthenticateFormHandler
{
  private final Log log = LogFactory.getLog(AuthenticateFormHandler.class);
  
  private String SESSION_KEY_LOGIN_CONTEXT;
  
  private String pwmLocation;
  
  private String pwmTemplateName;
  
  private List<String> pwdCrdVal;
  
  private int maxConsecutiveFailures;
  
  private LockingService accountLockingService;
  
  private boolean adminAllowsPasswordChanges;
  private boolean trackAuthenticationTime;
  private boolean enablePasswordExpiryNotification;
  private Long expiringPasswordWarningThreshold;
  private int rememberUsernameCookieLifetime;
  private String idpAdapterId;
  private String localIdentityProfileId;
  private String loginTemplateName;
  private String passwordExpiryTemplateName;
  private String loginChallengeTemplateName;
  private String cookieName;
  private String resetType;
  private boolean enableRememberMyUsername;
  private boolean allowUsernameEdits;
  private boolean enableUsernameRecovery;
  
  public AuthenticateFormHandler(String SESSION_KEY_LOGIN_CONTEXT, List<String> pwdCrdVal, boolean trackAuthenticationTime, int maxConsecutiveFailures, LockingService accountLockingService, boolean adminAllowsPasswordChanges, String pwmLocation, boolean enablePasswordExpiryNotification, String idpAdapterId, String localIdentityProfileId, String loginTemplateName, String passwordExpiryTemplateName, String cookieName, boolean enableUsernameRecovery, String resetType, boolean enableRememberMyUsername, boolean allowUsernameEdits, int rememberUsernameCookieLifetime, Long expiringPasswordWarningThreshold, String loginChallengeTemplateName, String pwmTemplateName)
  {
    this.SESSION_KEY_LOGIN_CONTEXT = SESSION_KEY_LOGIN_CONTEXT;
    this.pwdCrdVal = pwdCrdVal;
    this.trackAuthenticationTime = trackAuthenticationTime;
    this.maxConsecutiveFailures = maxConsecutiveFailures;
    this.accountLockingService = accountLockingService;
    this.adminAllowsPasswordChanges = adminAllowsPasswordChanges;
    this.pwmLocation = pwmLocation;
    this.enablePasswordExpiryNotification = enablePasswordExpiryNotification;
    this.idpAdapterId = idpAdapterId;
    this.localIdentityProfileId = localIdentityProfileId;
    this.loginTemplateName = loginTemplateName;
    this.cookieName = cookieName;
    this.enableUsernameRecovery = enableUsernameRecovery;
    this.enableRememberMyUsername = enableRememberMyUsername;
    this.allowUsernameEdits = allowUsernameEdits;
    this.resetType = resetType;
    this.rememberUsernameCookieLifetime = rememberUsernameCookieLifetime;
    this.passwordExpiryTemplateName = passwordExpiryTemplateName;
    this.expiringPasswordWarningThreshold = expiringPasswordWarningThreshold;
    this.loginChallengeTemplateName = loginChallengeTemplateName;
    this.pwmTemplateName = pwmTemplateName;
  }
  
  public AuthenticateFormHandler(String SESSION_KEY_LOGIN_CONTEXT, PasswordChangeConfiguration configuration, LockingService accountLockingService)
  {
    this.SESSION_KEY_LOGIN_CONTEXT = SESSION_KEY_LOGIN_CONTEXT;
    
    this.pwdCrdVal = configuration.getPcvIds();
    this.trackAuthenticationTime = configuration.isTrackAuthenticationTime();
    this.maxConsecutiveFailures = configuration.getNumInvalidAttempts();
    this.accountLockingService = accountLockingService;
    this.adminAllowsPasswordChanges = configuration.isAllowsChangePassword();
    this.pwmLocation = configuration.getPwmLocation();
    this.enablePasswordExpiryNotification = configuration.isEnablePasswordExpiryNotification();
    this.idpAdapterId = configuration.getAdapterId();
    this.loginTemplateName = configuration.getLoginTemplateName();
    this.cookieName = configuration.getCookieName();
    this.enableUsernameRecovery = configuration.isEnableUsernameRecovery();
    this.enableRememberMyUsername = configuration.isEnableRememberMyUsername();
    this.allowUsernameEdits = configuration.isAllowUsernameEdits();
    this.resetType = configuration.getResetType();
    this.rememberUsernameCookieLifetime = configuration.getRememberUsernameCookieLifetime();
    this.passwordExpiryTemplateName = configuration.getPasswordExpiryTemplateName();
    this.expiringPasswordWarningThreshold = configuration.getExpiringPasswordWarningThreshold();
    

    this.localIdentityProfileId = null;
    this.loginChallengeTemplateName = null;
    this.pwmTemplateName = null;
  }
  






  public HtmlFormLoginContext authenticateForm(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, AuthnPolicy authnPolicy, String entityId, String username, String password, String resumeUrl, String pcvId, TransactionalStateSupport transactionalStateSupport, boolean attemptToRecover, Object state, boolean isChainedUsernameAvailable, boolean updateCookieBeforeChallenge, boolean isPasswordChangeRequest)
    throws IOException
  {
    HtmlFormLoginContext oldLoginContext = (HtmlFormLoginContext)transactionalStateSupport.removeAttribute(this.SESSION_KEY_LOGIN_CONTEXT, req, resp);
    

    HtmlFormLoginContext loginContext = new HtmlFormLoginContext();
    if (oldLoginContext != null)
    {

      loginContext.setUserName(oldLoginContext.getUserName());
    }
    
    List<String> pcvList = new ArrayList();
    int errorCount = 0;
    

    boolean isPasswordExpiryNotifiable = false;
    
    if (StringUtils.isNotBlank(pcvId))
    {
      pcvList.add(pcvId);
    }
    else
    {
      pcvList.addAll(this.pwdCrdVal);
    }
    
    for (String pcv : pcvList)
    {
      boolean isChallengeQuestionPosted = false;
      isPasswordExpiryNotifiable = false;
      Map<String, AttributeValue> authnIds = null;
      
      try
      {
        PasswordCredentialValidator credentialValidator = new PasswordCredentialValidatorAccessor().getPasswordCredentialValidator(pcv);
        
        if ((credentialValidator instanceof ChangeablePasswordCredential))
        {
          ChangeablePasswordCredential changeablePasswordPCV = (ChangeablePasswordCredential)credentialValidator;
          isPasswordExpiryNotifiable = changeablePasswordPCV.isPendingPasswordExpiryNotifiable();
        }
        
        if ((state != null) && ((credentialValidator instanceof ChallengeablePasswordCredential)))
        {
          isChallengeQuestionPosted = true;
          ChallengeablePasswordCredential cpc = (ChallengeablePasswordCredential)credentialValidator;
          
          PasswordChallengeResult result = cpc.challenge(username, password, state);
          
          authnIds = new AttributeMap();
          authnIds.put("username", new AttributeValue(username));
          
          if (credentialValidator.getPluginDescriptor().isSupportsExtendedContract())
          {
            for (Entry<?, List<String>> attribute : result.getAttributes().entrySet())
            {
              authnIds.put(String.valueOf(attribute.getKey()), new AttributeValue((Collection)attribute.getValue()));
            }
          }
        }
        else
        {
          authnIds = credentialValidator.processPasswordCredential(username, password);
        }

        if (Util.isEmpty(authnIds))
        {
          if (loginContext.getPcvId() == null)
          {

            loginContext.setPcvId(pcv);
            loginContext.setAuthnIds(authnIds);
            loginContext.setException(AuthenticationResultEnum.INVALID_CREDENTIALS.newException());
            if (!loginContext.isRecoverable())
            {
              errorCount++;
            }

          }
        }
        else
        {
          loginContext.setPcvId(pcv);
          AuditLogger.setPcvId(pcv);
          if (this.trackAuthenticationTime)
          {
            Map<String, Object> attributes = new HashMap();
            attributes.putAll(authnIds);
            attributes.put("org.sourceid.saml20.adapter.idp.authn.authnInst", Long.valueOf(System.currentTimeMillis()));
            loginContext.setAuthnIds(attributes);
          }
          else
          {
            loginContext.setAuthnIds(authnIds);
          }
          loginContext.setException(null);

          errorCount = 0;
          break;
        }
      }
      catch (PasswordCredentialChallengeException e)
      {
        if (HtmlFormIdpAuthnAdapterUtils.supportsChallengeResponse(pcv))
        {
          errorCount = 0;
          loginContext.setException(e);
          loginContext.setPcvId(pcv);
          String userKey = req.getRemoteAddr() + username;

          if ((isChallengeQuestionPosted) && (authnIds == null))
          {
            this.accountLockingService.logFailedLogin(userKey);
            boolean locked = this.accountLockingService.isLocked(userKey, this.maxConsecutiveFailures, com.pingidentity.common.security.AccountLockingService.getLockoutPeriod());

            if ((loginContext.isError()) && (loginContext.isRecoverable()) && (!locked))
            {

              handlePasswordCredentialChallengeException(req, resp, inParameters, username, resumeUrl, transactionalStateSupport, e);
            }
            else
            {
              errorCount++;
            }
          }
          else
          {
            this.accountLockingService.clearFailedLogins(userKey);
            if (updateCookieBeforeChallenge)
            {
              HtmlFormIdpAuthnAdapter.updateUserNameCookie(req, resp, username, isChainedUsernameAvailable, this.allowUsernameEdits, this.rememberUsernameCookieLifetime, this.cookieName);
            }

            handlePasswordCredentialChallengeException(req, resp, inParameters, username, resumeUrl, transactionalStateSupport, e);
          }

          break;
        }


        loginContext.setPcvId(pcv);
        loginContext.setAuthnIds(null);
        loginContext.setException(e);



      }
      catch (PasswordCredentialValidatorAuthnException e)
      {


        if ((loginContext.getPcvId() == null) ||
          (!AuthenticationResultEnum.USER_NOT_FOUND.getMessageKey().equals(e.getMessageKey())))
        {
          loginContext.setPcvId(pcv);
          loginContext.setException(e);

          if (loginContext.isRecoverable())
          {

            errorCount = 0;
            if (attemptToRecover)
            {
              if (this.adminAllowsPasswordChanges)
              {
                if (HtmlFormIdpAuthnAdapterUtils.supportsPasswordChange(loginContext.getPcvId(), this.pwmLocation))
                {



                  saveLoginState(req, resp, username, transactionalStateSupport, loginContext);

                  HtmlFormIdpAuthnAdapter.promptForPasswordChange(req, resp, inParameters, authnPolicy, resumeUrl, loginContext
                    .getMessageKey(), isChainedUsernameAvailable, username, this.pwmLocation, this.pwmTemplateName, this.adminAllowsPasswordChanges, this.SESSION_KEY_LOGIN_CONTEXT);













                }
                else
                {













                  ChallengeWithForm form = new Builder().clientId((String)inParameters.get("com.pingidentity.adapter.input.parameter.oauth.client.id")).spAdapterId((String)inParameters.get("com.pingidentity.adapter.input.parameter.sp.adapter.id")).authnPolicy(authnPolicy).url(resumeUrl).name(username).loginFailed(true).entityId(entityId).errorMessageKey(null).authnMessageKey(loginContext.getMessageKey()).serverError(null).isChainedUsernameAvailable(isChainedUsernameAvailable).pwdCrdVal(this.pwdCrdVal).pwmLocation(this.pwmLocation).allowsChangePassword(this.adminAllowsPasswordChanges).loginTemplateName(this.loginTemplateName).idpAdapterId(this.idpAdapterId).entityId(entityId).localIdentityProfileId(this.localIdentityProfileId).cookieName(this.cookieName).resetType(this.resetType).enableRememberMyUsername(this.enableRememberMyUsername).allowUsernameEdits(this.allowUsernameEdits).enableUsernameRecovery(this.enableUsernameRecovery).resetType(this.resetType).build();
                  form.render(req, resp);

                  loginContext.setAuthnIds(null);

                  this.log.debug("Password Credential Validator " + loginContext.getPcvId() + " doesn't support password changes.");








                }









              }
              else
              {








                ChallengeWithForm form = new Builder().clientId((String)inParameters.get("com.pingidentity.adapter.input.parameter.oauth.client.id")).spAdapterId((String)inParameters.get("com.pingidentity.adapter.input.parameter.sp.adapter.id")).authnPolicy(authnPolicy).url(resumeUrl).name(username).loginFailed(true).entityId(entityId).errorMessageKey(null).authnMessageKey(loginContext.getMessageKey()).serverError(null).isChainedUsernameAvailable(isChainedUsernameAvailable).pwdCrdVal(this.pwdCrdVal).pwmLocation(this.pwmLocation).allowsChangePassword(this.adminAllowsPasswordChanges).loginTemplateName(this.loginTemplateName).idpAdapterId(this.idpAdapterId).entityId(entityId).localIdentityProfileId(this.localIdentityProfileId).cookieName(this.cookieName).resetType(this.resetType).enableRememberMyUsername(this.enableRememberMyUsername).allowUsernameEdits(this.allowUsernameEdits).enableUsernameRecovery(this.enableUsernameRecovery).resetType(this.resetType).build();
                form.render(req, resp);
              }
            }
            break;
          }
          if (!AuthenticationResultEnum.USER_NOT_FOUND.getMessageKey().equals(e.getMessageKey()))
          {

            errorCount++;
          }
        }
        else
        {
          this.log.debug("'User Not Found' error in Password Credential Validator '" + loginContext.getPcvId() + "' ignored because an authentication error has occurred in another PCV.");
        }
        

      }
      catch (Exception e)
      {
        loginContext.setPcvId(pcv);
        loginContext.setException(AuthenticationResultEnum.getDefaultValue().newException());
        this.log.error(e.getMessage(), e);
        if (!loginContext.isRecoverable())
        {
          errorCount++;
        }
      }
    }
    
    if (errorCount > 1)
    {
      loginContext.setPcvId(null);
      loginContext.setException(AuthenticationResultEnum.getDefaultValue().newException());
      loginContext.setAuthnIds(null);
      loginContext.setUserName(username);
      this.log.debug("Multiple non-recoverable errors in Password Credential Validators.  A general authentication error will be returned.");
    }
    else if (this.enablePasswordExpiryNotification)
    {
      if ((this.adminAllowsPasswordChanges) && (isPasswordExpiryNotifiable) && (!isPasswordChangeRequest))
      {
        try
        {
          handleExpiringPasswordWarning(req, resp, resumeUrl, loginContext, username, inParameters);
        }
        catch (TemplateRendererUtilException e)
        {
          this.log.error(e.getMessage(), e);
        }
      }
    }
    else
    {
      HtmlFormIdpAuthnAdapterUtils.addCookie("pf-hfa-exp-pwd", "", 0, resp);
    }
    
    return loginContext;
  }
  


  private void handleExpiringPasswordWarning(HttpServletRequest req, HttpServletResponse resp, String resumeUrl, HtmlFormLoginContext loginContext, String username, Map<String, Object> inParameters)
    throws TemplateRendererUtilException
  {
    if ((loginContext != null) && (loginContext.getAuthnIds() != null))
    {
      String pendingPwdCookieValue = HtmlFormIdpAuthnAdapter.getPendingPwdCookieValue(loginContext.getPcvId(), username);
      String cookieValue = CookieMonster.getCookieValue("pf-hfa-exp-pwd", req);
      boolean isSnoozed = false;
      if ((StringUtils.isNotBlank(cookieValue)) && (cookieValue.equals(pendingPwdCookieValue)))
      {
        isSnoozed = true;
      }
      else
      {
        HtmlFormIdpAuthnAdapterUtils.addCookie("pf-hfa-exp-pwd", "", 0, resp);
      }
      
      if ((!isSnoozed) && (loginContext.getAuthnIds().containsKey("passwordExpiryTime")))
      {
        String passwordExpiryTime = loginContext.getAuthnIds().get("passwordExpiryTime").toString();
        if (StringUtils.isNotBlank(passwordExpiryTime))
        {

          Long expiryDuration = Long.valueOf(Long.parseLong(passwordExpiryTime) - new Date().getTime());
          if ((expiryDuration.longValue() > 0L) && (expiryDuration.longValue() <= this.expiringPasswordWarningThreshold.longValue()))
          {
            TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(resumeUrl);
            saveLoginState(req, resp, username, transactionalStateSupport, loginContext);
            Long timeToExpire = Long.valueOf(TimeUnit.MILLISECONDS.toDays(expiryDuration.longValue()));
            String daysToExpire = String.valueOf(timeToExpire.intValue());
            String pcvId = loginContext.getPcvId();
            Map<String, Object> params = new HashMap();
            String clientId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.oauth.client.id");
            String spAdapterId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.sp.adapter.id");
            

            params.put("adapterId", this.idpAdapterId);
            params.put("name", "pf.username");
            params.put("username", HTMLEncoder.encode(username) == null ? "" : HTMLEncoder.encode(username));
            params.put("pass", "pf.pass");
            params.put("ok", "pf.ok");
            params.put("cancel", "pf.notificationCancel");
            params.put("baseUrl", MgmtFactory.getLocalSettingsManager().getLocalSettings().getBaseUrl());
            
            params.put("changePassword", "ChangePassword");
            params.put("resumeUrl", resumeUrl);
            params.put("passwordExpiring", "pf.passwordExpiring");
            params.put("pcvId", pcvId);
            params.put("pcvIdField", "pf.pcvId");
            params.put("daysToExpire", daysToExpire);
            params.put(Parameters.CLIENT_ID, clientId);
            params.put("spAdapterId", spAdapterId);
            
            TemplateRendererUtil.render(req, resp, this.passwordExpiryTemplateName, params);
          }
        }
      }
    }
  }
  




  public void saveLoginState(HttpServletRequest req, HttpServletResponse resp, String username, TransactionalStateSupport transactionalStateSupport, HtmlFormLoginContext loginContext)
  {
    loginContext.setUserName(username);
    transactionalStateSupport.setAttribute(this.SESSION_KEY_LOGIN_CONTEXT, loginContext, req, resp);
  }
  








  private void handlePasswordCredentialChallengeException(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, String username, String resumeUrl, TransactionalStateSupport transactionalStateSupport, PasswordCredentialChallengeException exception)
    throws IOException
  {
    String replyMessage = null;
    String errorMessageKey = null;
    Object state = null;
    boolean isRadiusException = (exception.getCause() != null) && ((exception.getCause() instanceof RadiusAdminUserException));
    
    if (isRadiusException)
    {
      RadiusAdminUserException re = (RadiusAdminUserException)exception.getCause();
      state = re.getState();
      replyMessage = re.getReplyMessage();
    }
    else
    {
      state = exception.getState();
      replyMessage = exception.getMessageKey();
    }
    
    if (replyMessage == null)
    {
      errorMessageKey = "challengeResponseBlankError";
    }
    
    transactionalStateSupport.setAttribute("radius-state", state, req, resp);
    transactionalStateSupport.setAttribute("radius-username", username, req, resp);
    transactionalStateSupport.setAttribute("radius-reply-message", replyMessage, req, resp);
    
    loginChallengeWithForm(req, resp, inParameters, resumeUrl, replyMessage, errorMessageKey);
  }
  


  private void loginChallengeWithForm(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, String url, String challengeQuestion, String errorMessageKey)
    throws IOException
  {
    String clientId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.oauth.client.id");
    String spAdapterId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.sp.adapter.id");
    
    Map<String, Object> params = new HashMap();
    
    params.put("url", url);
    params.put("ok", "pf.ok");
    params.put("challengeResponse", "pf.challengeResponse");
    params.put("cancel", "pf.cancel");
    params.put("challengeQuestion", challengeQuestion);
    params.put("errorMessageKey", errorMessageKey);
    params.put(Parameters.CLIENT_ID, clientId);
    params.put("spAdapterId", spAdapterId);
    
    TemplateRendererUtil.render(req, resp, this.loginChallengeTemplateName, params);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\idp\AuthenticateFormHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */