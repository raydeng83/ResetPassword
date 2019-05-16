package com.efx.pingfed.adapters.htmlform.idp;

import com.pingidentity.access.PasswordCredentialValidatorAccessor;
import com.pingidentity.adapter.support.LogoutHandler;
import com.efx.pingfed.adapters.htmlform.config.HtmlFormGuiConfiguration;
import com.pingidentity.adapters.htmlform.idp.AuthenticateFormHandler;
import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapterUtils;
import com.pingidentity.adapters.htmlform.idp.HtmlFormLoginContext;
import com.pingidentity.adapters.htmlform.idrecovery.servlet.RecoverUsernameServlet;
import com.pingidentity.adapters.htmlform.pwdchange.common.ChangePasswordSessionState;
import com.pingidentity.adapters.htmlform.pwdchange.common.ChangePasswordSessionState.Builder;
import com.pingidentity.adapters.htmlform.pwdreset.servlet.AccountUnlockServlet;
import com.pingidentity.adapters.htmlform.pwdreset.servlet.ErrorServlet;
import com.pingidentity.adapters.htmlform.pwdreset.servlet.PingIDServlet;
import com.pingidentity.adapters.htmlform.pwdreset.servlet.ResetServlet;
import com.pingidentity.adapters.htmlform.pwdreset.servlet.ResumeServlet;
import com.efx.pingfed.adapters.htmlform.pwdreset.servlet.SecurityCodeServlet;
import com.pingidentity.adapters.htmlform.session.HtmlFormSessionStateSupport;
import com.pingidentity.captcha.CaptchaServerSideValidator;
import com.pingidentity.captcha.CaptchaValidationError;
import com.pingidentity.common.security.AccountLockingService;
import com.pingidentity.common.security.InputValidator;
import com.pingidentity.common.security.LockingService;
import com.pingidentity.common.security.UsernameRule;
import com.pingidentity.common.security.ValidationRule;
import com.pingidentity.common.util.CookieMonster;
import com.pingidentity.common.util.EOLUtil;
import com.pingidentity.common.util.HTMLEncoder;
import com.pingidentity.localidentity.LocalIdentityProfile;
import com.pingidentity.localidentity.mgmt.LocalIdentityManager;
import com.pingidentity.sdk.AuthenticationSession;
import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;
import com.pingidentity.sdk.SessionAwareAuthenticationAdapter;
import com.pingidentity.sdk.password.PasswordCredentialChallengeException;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.RecoverableUsername;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.io.IOException;
import java.io.Serializable;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONException;
import org.sourceid.common.Util;
import org.sourceid.common.VersionUtil;
import org.sourceid.oauth20.protocol.Parameters;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;
import org.sourceid.saml20.adapter.state.SessionStateSupport;
import org.sourceid.saml20.adapter.state.TransactionalStateSupport;
import org.sourceid.saml20.domain.CaptchaSettings;
import org.sourceid.saml20.domain.LocalSettings;
import org.sourceid.saml20.domain.SpConnection;
import org.sourceid.saml20.domain.mgmt.CaptchaManager;
import org.sourceid.saml20.domain.mgmt.LocalSettingsManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.validation.CommonValidator;
import org.sourceid.saml20.metadata.MetaDataFactory;
import org.sourceid.saml20.metadata.partner.MetadataDirectory;
import org.sourceid.saml20.service.impl.proxy.LockingServiceFactory;
import org.sourceid.websso.servlet.adapter.HandlerRegistry;

public class ForgotPasswordHtmlFormIdpAuthnAdapter implements IdpAuthenticationAdapterV2, SessionAwareAuthenticationAdapter
{
  private static final Log log = LogFactory.getLog(ForgotPasswordHtmlFormIdpAuthnAdapter.class);
  private static final String ADAPTER_NAME = "Forgot Password HTML Form IdP Adapter";
  private final HtmlFormSessionStateSupport sessionStateSupport = new HtmlFormSessionStateSupport();
  private final HtmlFormGuiConfiguration httpFormGuiConfiguration = new HtmlFormGuiConfiguration();
  
  private LockingService accountLockingService;
  
  private Configuration config;
  
  private int maxConsecutiveFailures;
  private final List<String> pwdCrdVal = new ArrayList();
  private Integer sessionTimeout = null;
  private Integer sessionMaxTimeout = null;
  

  private String loginTemplateName = null;
  private String logoutRedirectLocation = null;
  private String logoutTemplateName = null;
  private String logoutSubPath = null;
  private String sessionState = null;
  private String loginChallengeTemplateName = null;
  private boolean adminAllowsPasswordChanges = false;
  private boolean enableRememberUsername = false;
  private int rememberUsernameCookieLifetime = Integer.parseInt("30");
  private String pwmLocation = null;
  private String pwmTemplateName = null;
  private boolean allowUsernameEdits = false;
  private boolean trackAuthenticationTime;
  private boolean enablePasswordExpiryNotification = false;
  private String passwordExpiryTemplateName = null;
  private Long expiringPasswordWarningThreshold = Long.valueOf(604800000L);
  private int expiringPasswordSnoozeInterval = 86400;
  private String changePasswordEmailNotificationTemplateName = null;
  private String resetType = null;
  
  public static final String USERNAME_FIELD = "pf.username";
  
  private static final String ADAPTER_ID_FIELD = "pf.adapterId";
  
  private static final String PASS = "pf.pass";
  
  private static final String CHANGE_PASSWORD = "ChangePassword";
  
  static final String CHALLENGE_RESPONSE = "pf.challengeResponse";
  
  static final String OK = "pf.ok";
  
  static final String CANCEL = "pf.cancel";
  
  private static final String REMEMBER_USERNAME = "pf.rememberUsername";
  
  public static final String PASSWORD_RESET_FIELD = "pf.passwordreset";
  
  private static final String USERNAME_RECOVERY_FIELD = "pf.usernamerecovery";
  private static final String PCV_ID_FIELD = "pf.pcvId";
  private static final String PASSWORD_EXPIRING = "pf.passwordExpiring";
  private static final String NOTIFICATION_CANCEL = "pf.notificationCancel";
  static final String SESSION_KEY_RADIUS_STATE = "radius-state";
  static final String SESSION_KEY_RADIUS_USERNAME = "radius-username";
  static final String SESSION_KEY_RADIUS_REPLY_MESSAGE = "radius-reply-message";
  private static final String ALTERNATE_AUTHN_SYSTEM = "pf.alternateAuthnSystem";
  private static final String REGISTRATION = "pf.registration";
  private String SESSION_KEY_AUTHN;
  private String SESSION_KEY_FIRST_ACTIVITY;
  private String SESSION_KEY_LAST_ACTIVITY;
  private String SESSION_KEY_LOGIN_CONTEXT = null;
  
  public static final String ERROR_CHALLENGE_RESPONSE_BLANK = "challengeResponseBlankError";
  
  private String cookieName;
  
  static final String COOKIE_NAME_PREFIX = "pf-hfa-";
  
  static final String COOKIE_NAME_SUFFIX = "-rmu";
  public static final String EXPIRING_PASSWORD_COOKIE_NAME = "pf-hfa-exp-pwd";
  private String localIdentityProfileId;
  
  public static class KeyValuePair
    implements Serializable
  {
    private String key;
    private String value;
    
    public KeyValuePair(String key, String value)
    {
      this.key = key;
      this.value = value;
    }
    
    public String getKey() {
      return this.key;
    }
    
    public void setKey(String key) {
      this.key = key;
    }
    
    public String getValue() {
      return this.value;
    }
    
    public void setValue(String value) {
      this.value = value;
    }
  }
  


  public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp, String entityId, AuthnPolicy authnPolicy, String resumeUrl)
    throws IOException
  {
    throw new UnsupportedOperationException();
  }
  




  private HtmlFormLoginContext handleLoginForm(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, String entityId, AuthnPolicy authnPolicy, String resumeUrl, HtmlFormLoginContext loginContext, String username, boolean isChainedUsernameAvailable)
    throws IOException
  {
    String password = req.getParameter(PASS);
    String challengeResponse = req.getParameter(CHALLENGE_RESPONSE);
    String hiddenAdapterId = req.getParameter(ADAPTER_ID_FIELD);
    

    if ((hiddenAdapterId != null) && (!hiddenAdapterId.equals(this.config.getId())))
    {
      password = null;
    }
    
    boolean changePassword = "true".equalsIgnoreCase(req.getParameter(CHANGE_PASSWORD));
    boolean challengeResponsePosted = challengeResponse != null;
    boolean loginFormPosted = (username != null) && (password != null);
    
    if (loginFormPosted)
    {
      loginContext = doLoginFormPosted(req, resp, inParameters, entityId, authnPolicy, resumeUrl, loginContext, username, password, isChainedUsernameAvailable);


    }
    else if (changePassword)
    {

      promptForPasswordChange(req, resp, inParameters, authnPolicy, resumeUrl, null, isChainedUsernameAvailable, username, this.pwmLocation, this.pwmTemplateName, this.adminAllowsPasswordChanges, this.SESSION_KEY_LOGIN_CONTEXT);

    }
    else if (challengeResponsePosted)
    {
      loginContext = doChallengeRespPosted(req, resp, inParameters, entityId, authnPolicy, resumeUrl, challengeResponse, isChainedUsernameAvailable);

    }
    else
    {

      doLoginFormRequested(req, resp, inParameters, entityId, authnPolicy, resumeUrl, loginContext, username, isChainedUsernameAvailable);
    }
    
    return loginContext;
  }
  


  public boolean checkUseAuthenticationSession(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, AuthenticationSession existingSession)
  {
    boolean result = getRequestedActionFromInParams(inParameters) == null;
    if (!result)
    {
      if (log.isDebugEnabled())
      {
        log.debug("Ignoring existing authentication session as policy.action was found in inParameters");
      }
    }
    return result;
  }
  



  private void doLoginFormRequested(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, String entityId, AuthnPolicy authnPolicy, String resumeUrl, HtmlFormLoginContext loginContext, String username, boolean isChainedUsernameAvailable)
    throws IOException
  {
    if (isSessionTracking())
    {
      boolean isSessionExpired = this.sessionStateSupport.isSessionExpired(this.SESSION_KEY_LAST_ACTIVITY, this.sessionTimeout, req, resp);
      boolean isSessionMaxExpired = isSessionMaxExpired(req, resp);
      if ((isSessionExpired) || (isSessionMaxExpired))
      {
        this.sessionStateSupport.removeAttribute(this.SESSION_KEY_AUTHN, req, resp);
        loginContext.setAuthnIds(null);
      }
      else
      {
        loginContext.setAuthnIds((Map)this.sessionStateSupport.getAttribute(this.SESSION_KEY_AUTHN, req, resp));
      }
    }
    
    handleExpiringPasswordWarningCancel(req, resp, resumeUrl, loginContext);
    
    if ((Util.isEmpty(loginContext.getAuthnIds())) || (authnPolicy.reauthenticate()))
    {
      boolean enableCookie = enableRememberChainedUsername(isChainedUsernameAvailable);
      if (enableCookie)
      {
        String cookieValue = CookieMonster.getCookieValue(this.cookieName, req);
        if ((!this.enableRememberUsername) && (StringUtils.isNotBlank(cookieValue)))
        {


          HtmlFormIdpAuthnAdapterUtils.addCookie(this.cookieName, "", 0, resp);


        }
        else if (StringUtils.isNotBlank(cookieValue))
        {



          username = cookieValue;
        }
      }
      

      challengeWithForm(req, resp, inParameters, authnPolicy, resumeUrl, username, false, entityId, null, null, null, isChainedUsernameAvailable);


    }
    else if (isSessionTracking())
    {
      this.sessionStateSupport.refreshSession(this.SESSION_KEY_LAST_ACTIVITY, req, resp);
    }
  }
  

  private void handleExpiringPasswordWarningCancel(HttpServletRequest req, HttpServletResponse resp, String resumeUrl, HtmlFormLoginContext loginContext)
  {
    String pcvId = null;
    HtmlFormLoginContext notificationLoginContext = null;
    if (Util.isEmpty(loginContext.getAuthnIds()))
    {
      TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(resumeUrl);
      notificationLoginContext = (HtmlFormLoginContext)transactionalStateSupport.getAttribute(this.SESSION_KEY_LOGIN_CONTEXT, req, resp);
      if (notificationLoginContext != null)
      {
        pcvId = notificationLoginContext.getPcvId();
      }
    }
    else if ((req.getParameter(PCV_ID_FIELD) != null) && (CommonValidator.isValidAdapterInstanceId(req.getParameter(PCV_ID_FIELD))))
    {
      notificationLoginContext = loginContext;
      pcvId = EOLUtil.stripEOLs(req.getParameter(PCV_ID_FIELD));
    }
    
    if ((notificationLoginContext != null) && (!Util.isEmpty(notificationLoginContext.getAuthnIds())))
    {
      Object authenticatedUser = notificationLoginContext.getAuthnIds().get("username");
      if (authenticatedUser != null)
      {
        boolean isResetPendingPassword = isResetPendingPassword(req);
        
        if ((StringUtils.isNotBlank(req.getParameter(NOTIFICATION_CANCEL))) && (isResetPendingPassword))
        {
          String pendingPwdCookieValue = getPendingPwdCookieValue(pcvId, authenticatedUser.toString());
          if ((StringUtils.isNotBlank(pendingPwdCookieValue)) && (this.expiringPasswordSnoozeInterval > 0))
          {
            HtmlFormIdpAuthnAdapterUtils.addCookie(EXPIRING_PASSWORD_COOKIE_NAME, pendingPwdCookieValue, this.expiringPasswordSnoozeInterval, resp);
          }
        }
      }
      loginContext.setAuthnIds(notificationLoginContext.getAuthnIds());
    }
  }
  
  private static boolean isResetPendingPassword(HttpServletRequest req)
  {
    return (StringUtils.isNotBlank(req.getParameter(PASSWORD_EXPIRING))) && 
      (Boolean.TRUE.toString().equals(req.getParameter(PASSWORD_EXPIRING)));
  }
  





  private HtmlFormLoginContext doChallengeRespPosted(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, String entityId, AuthnPolicy authnPolicy, String resumeUrl, String challengeResponse, boolean isChainedUsernameAvailable)
    throws IOException
  {
    TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(resumeUrl);
    
    String username = (String)transactionalStateSupport.removeAttribute(SESSION_KEY_RADIUS_USERNAME, req, resp);
    Object state = transactionalStateSupport.removeAttribute(SESSION_KEY_RADIUS_STATE, req, resp);
    


    AuthenticateFormHandler authenticateFormHandler = new AuthenticateFormHandler(this.SESSION_KEY_LOGIN_CONTEXT, this.pwdCrdVal, this.trackAuthenticationTime, this.maxConsecutiveFailures, this.accountLockingService, this.adminAllowsPasswordChanges, this.pwmLocation, this.enablePasswordExpiryNotification, this.config.getId(), this.localIdentityProfileId, this.loginTemplateName, this.passwordExpiryTemplateName, this.cookieName, this.enableRememberUsername, this.resetType, this.enableRememberUsername, this.allowUsernameEdits, this.rememberUsernameCookieLifetime, this.expiringPasswordWarningThreshold, this.loginChallengeTemplateName, this.pwmTemplateName);
    




    HtmlFormLoginContext loginContext = authenticateFormHandler.authenticateForm(req, resp, inParameters, authnPolicy, entityId, username, challengeResponse, resumeUrl, null, transactionalStateSupport, true, state, isChainedUsernameAvailable, false, false);
    


    if (loginContext.isSuccess())
    {
      this.accountLockingService.clearFailedLogins(req.getRemoteAddr() + username);
      
      if ((isSessionTracking()) && (!Util.isEmpty(loginContext.getAuthnIds())))
      {
        this.sessionStateSupport.setAttribute(this.SESSION_KEY_AUTHN, loginContext.getAuthnIds(), req, resp, true);
        this.sessionStateSupport.refreshSession(this.SESSION_KEY_LAST_ACTIVITY, req, resp);
        this.sessionStateSupport.refreshSession(this.SESSION_KEY_FIRST_ACTIVITY, req, resp);
      }
    }
    return loginContext;
  }
  
  static String getPendingPwdCookieValue(String pcvId, String username)
  {
    if ((pcvId != null) && (username != null))
    {
      return pcvId + "-" + username;
    }
    
    return "";
  }
  




  private HtmlFormLoginContext doLoginFormPosted(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, String entityId, AuthnPolicy authnPolicy, String resumeUrl, HtmlFormLoginContext loginContext, String username, String password, boolean isChainedUsernameAvailable)
    throws IOException
  {
    if (StringUtils.isNotBlank(req.getParameter(CANCEL)))
    {

      TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(resumeUrl);
      transactionalStateSupport.removeAttribute(this.SESSION_KEY_LOGIN_CONTEXT, req, resp);
      loginContext.setAuthnIds(null);
    }
    else if (StringUtils.isNotBlank(req.getParameter(ALTERNATE_AUTHN_SYSTEM)))
    {
      TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(resumeUrl);
      transactionalStateSupport.removeAttribute(this.SESSION_KEY_LOGIN_CONTEXT, req, resp);
      Map<String, Object> attributes = new HashMap();
      attributes.put("policy.action", req.getParameter(ALTERNATE_AUTHN_SYSTEM));
      loginContext.setAuthnIds(attributes);
      loginContext.setUserName(null);
      loginContext.setAlternateAuthnSystem(true);

    }
    else if (Boolean.parseBoolean(req.getParameter(REGISTRATION)))
    {
      TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(resumeUrl);
      transactionalStateSupport.removeAttribute(this.SESSION_KEY_LOGIN_CONTEXT, req, resp);
      Map<String, Object> attributes = new HashMap();
      attributes.put("policy.action", "identity.registration");
      loginContext.setAuthnIds(attributes);
      loginContext.setUserName(null);
      loginContext.setAlternateAuthnSystem(true);

    }
    else
    {
      try
      {
        if (isCaptchaEnabledAuthentication(this.config))
        {
          CaptchaServerSideValidator captchaServerSideValidator = new CaptchaServerSideValidator(req, MgmtFactory.getCaptchaManager().getCaptchaSettings().getSecretKey());
          boolean isValid = captchaServerSideValidator.validateRecaptcha();
          
          if (!isValid)
          {
            log.debug("Login failed: reCAPTCHA validation failure.");
            if (captchaServerSideValidator.hasErrors())
            {
              for (CaptchaValidationError captchaValidationError : captchaServerSideValidator.getErrors())
              {
                log.error("Login failed due to: " + captchaValidationError.getErrorId() + " - " + captchaValidationError.getMessage());
              }
            }
            TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(resumeUrl);
            transactionalStateSupport.removeAttribute(this.SESSION_KEY_LOGIN_CONTEXT, req, resp);
            loginContext.setAuthnIds(null);
            return loginContext;
          }
        }
      }
      catch (JSONException e)
      {
        TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(resumeUrl);
        transactionalStateSupport.removeAttribute(this.SESSION_KEY_LOGIN_CONTEXT, req, resp);
        loginContext.setAuthnIds(null);
        return loginContext;
      }
      
      InputValidator.validate(USERNAME_FIELD, username, new ValidationRule[] { new UsernameRule() });
      
      String userKey = req.getRemoteAddr() + username;
      
      if (!this.accountLockingService.isLocked(userKey, this.maxConsecutiveFailures, 
        AccountLockingService.getLockoutPeriod()))
      {



        TransactionalStateSupport transactionalStateSupport = new TransactionalStateSupport(resumeUrl);
        


        AuthenticateFormHandler authenticateFormHandler = new AuthenticateFormHandler(this.SESSION_KEY_LOGIN_CONTEXT, this.pwdCrdVal, this.trackAuthenticationTime, this.maxConsecutiveFailures, this.accountLockingService, this.adminAllowsPasswordChanges, this.pwmLocation, this.enablePasswordExpiryNotification, this.config.getId(), this.localIdentityProfileId, this.loginTemplateName, this.passwordExpiryTemplateName, this.cookieName, this.enableRememberUsername, this.resetType, this.enableRememberUsername, this.allowUsernameEdits, this.rememberUsernameCookieLifetime, this.expiringPasswordWarningThreshold, this.loginChallengeTemplateName, this.pwmTemplateName);
        




        loginContext = authenticateFormHandler.authenticateForm(req, resp, inParameters, authnPolicy, entityId, username, password, resumeUrl, null, transactionalStateSupport, true, null, isChainedUsernameAvailable, true, false);
        


        if (Util.isEmpty(loginContext.getAuthnIds()))
        {


          if (!(loginContext.getException() instanceof PasswordCredentialChallengeException))
          {
            this.accountLockingService.logFailedLogin(userKey);
          }
          if ((loginContext.isError()) && 
            (!loginContext.isRecoverable()) && 
            (!this.accountLockingService.isLocked(userKey, this.maxConsecutiveFailures, 
            AccountLockingService.getLockoutPeriod())))
          {
            challengeWithForm(req, resp, inParameters, authnPolicy, resumeUrl, username, true, entityId, null, loginContext
              .getMessageKey(), loginContext.getRadiusServerError(), isChainedUsernameAvailable);
          }
          
        }
        else
        {
          this.accountLockingService.clearFailedLogins(userKey);
          
          if (isSessionTracking())
          {
            this.sessionStateSupport.setAttribute(this.SESSION_KEY_AUTHN, loginContext.getAuthnIds(), req, resp, true);
            this.sessionStateSupport.refreshSession(this.SESSION_KEY_LAST_ACTIVITY, req, resp);
            this.sessionStateSupport.refreshSession(this.SESSION_KEY_FIRST_ACTIVITY, req, resp);
          }
          updateUserNameCookie(req, resp, username, isChainedUsernameAvailable, this.allowUsernameEdits, this.rememberUsernameCookieLifetime, this.cookieName);
        }
      }
    }
    return loginContext;
  }
  

  static void updateUserNameCookie(HttpServletRequest req, HttpServletResponse resp, String username, boolean isChainedUsernameAvailable, boolean allowUsernameEdits, int rememberUsernameCookieLifetime, String cookieName)
  {
    boolean enableCookieForChainedUsername = enableRememberChainedUsername(isChainedUsernameAvailable, allowUsernameEdits);
    

    if (enableCookieForChainedUsername)
    {
      boolean rememberUsername = "on".equalsIgnoreCase(req.getParameter(REMEMBER_USERNAME));
      int age = rememberUsername ? getRememberUsernameCookieLifetime(rememberUsernameCookieLifetime) : 0;
      

      String cookieValue = rememberUsername ? username : "";
      HtmlFormIdpAuthnAdapterUtils.addCookie(cookieName, cookieValue, age, resp);
    }
  }
  
  public static int getRememberUsernameCookieLifetime(int cookieLifetime)
  {
    return 86400 * cookieLifetime;
  }
  
  private boolean enableRememberChainedUsername(boolean isChainedUsernameAvailable)
  {
    return enableRememberChainedUsername(isChainedUsernameAvailable, this.allowUsernameEdits);
  }
  
  public static boolean enableRememberChainedUsername(boolean isChainedUsernameAvailable, boolean allowUsernameEdits)
  {
    return (!isChainedUsernameAvailable) || (allowUsernameEdits);
  }
  
  private boolean isSessionTracking()
  {
    return !this.sessionState.equals("None");
  }
  



  private void challengeWithForm(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, AuthnPolicy authnPolicy, String url, String name, boolean loginFailed, String entityId, String errorMessageKey, String authnMessageKey, String serverError, boolean isChainedUsernameAvailable)
    throws IOException
  {
    if (authnPolicy.allowUserInteraction())
    {
      Map<String, Object> params = new HashMap();
      
      MetadataDirectory metadataDirectory = MetaDataFactory.getMetadataDirectory();
      SpConnection spConn = metadataDirectory.getSpConnection(entityId, false);
      String connectionName = spConn != null ? spConn.getName() : entityId;
      boolean usernameEditable = enableRememberChainedUsername(isChainedUsernameAvailable);
      boolean rememberChainedUsername = enableRememberChainedUsername(isChainedUsernameAvailable);
      String baseUrl = MgmtFactory.getLocalSettingsManager().getLocalSettings().getBaseUrl();
      String clientId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.oauth.client.id");
      String spAdapterId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.sp.adapter.id");
      
      params.put("url", url);
      params.put("adapterIdField", ADAPTER_ID_FIELD);
      params.put("adapterId", this.config.getId());
      params.put("name", USERNAME_FIELD);
      params.put("username", HTMLEncoder.encode(name) == null ? "" : HTMLEncoder.encode(name));
      params.put("usernameEditable", Boolean.valueOf(usernameEditable));
      params.put("isChainedUsernameAvailable", Boolean.valueOf(isChainedUsernameAvailable));
      params.put("pass", PASS);
      params.put("ok", OK);
      params.put("cancel", CANCEL);
      params.put("passwordReset", PASSWORD_RESET_FIELD);
      params.put("usernameRecovery", USERNAME_RECOVERY_FIELD);
      params.put("loginFailed", Boolean.valueOf(loginFailed));
      params.put("connectionName", connectionName);
      params.put("entityId", entityId);
      params.put("baseUrl", baseUrl);
      params.put("supportsPasswordChange", Boolean.valueOf((this.adminAllowsPasswordChanges) && (supportsPasswordChange(this.pwdCrdVal, this.pwmLocation))));
      params.put("supportsPasswordReset", Boolean.valueOf((this.adminAllowsPasswordChanges) && (supportsPasswordReset(this.pwdCrdVal)) && (!isResetTypeNone(this.config))));
      params.put("supportsUsernameRecovery", Boolean.valueOf(supportsUsernameRecovery(this.config, this.pwdCrdVal)));
      
      params.put("enableRememberUsername", Boolean.valueOf((rememberChainedUsername) && (this.enableRememberUsername)));
      params.put("rememberUsername", REMEMBER_USERNAME);
      
      String cookieValue = CookieMonster.getCookieValue(this.cookieName, req);
      params.put("rememberUsernameCookieExists", Boolean.valueOf(StringUtils.isNotBlank(cookieValue)));
      
      params.put("changePassword", CHANGE_PASSWORD);
      
      Map<String, String> changePasswordParam = getChangePasswordParam();
      params.put("changePasswordUrl", Util.appendQueryParams(url, changePasswordParam));
      params.put("forgotPasswordUrl", getForgetPasswordUrl(baseUrl, this.config.getId(), url));
      params.put("recoverUsernameUrl", getRecoverUsernameUrl(baseUrl, this.config.getId(), url));
      params.put("errorMessageKey", errorMessageKey);
      params.put("authnMessageKey", authnMessageKey);
      params.put("serverError", serverError);
      params.put("spAdapterId", spAdapterId);
      params.put(Parameters.CLIENT_ID, clientId);
      params.put("captchaEnabled", Boolean.valueOf(isCaptchaEnabledAuthentication(this.config)));
      if (isCaptchaEnabledAuthentication(this.config))
      {
        params.put("siteKey", MgmtFactory.getCaptchaManager().getCaptchaSettings().getSiteKey());
      }
      if (this.localIdentityProfileId != null)
      {
        LocalIdentityProfile lip = MgmtFactory.getLocalIdentityProfileManager().getProfile(this.localIdentityProfileId);
        if (lip != null)
        {
          params.put("altAuthSources", lip.getAuthSourceStrings());
          params.put("registrationEnabled", Boolean.valueOf(lip.isRegistrationEnabled()));
          params.put("registrationValue", REGISTRATION);
          params.put("alternateAuthnSystem", ALTERNATE_AUTHN_SYSTEM);
        }
      }
      TemplateRendererUtil.render(req, resp, this.loginTemplateName, params);
    }
  }
  
  public static String getForgetPasswordUrl(String baseUrl, String adapterId, String resumeUrl) throws IOException
  {
    String forgotPasswordEndpoint = baseUrl + "/ext/pwdreset/Identify?" + "AdapterId" + "=%s%s";
    
    if ((StringUtils.isNotBlank(resumeUrl)) && (!StringUtils.startsWithIgnoreCase(resumeUrl, "http")))
    {
      resumeUrl = baseUrl + resumeUrl;
    }
    
    String optionalTargetResource = StringUtils.isNotBlank(resumeUrl) ? "&TargetResource=" + URLEncoder.encode(resumeUrl, "UTF-8") : "";
    
    return String.format(forgotPasswordEndpoint, new Object[] {
      URLEncoder.encode(adapterId, "UTF-8"), optionalTargetResource });
  }
  
  private static String getChangePasswordUrl(String adapterId, String resumeUrl)
    throws IOException
  {
    String baseUrl = MgmtFactory.getLocalSettingsManager().getLocalSettings().getBaseUrl();
    
    String changePasswordEndpoint = baseUrl + "/ext/pwdchange/Identify?" + "AdapterId" + "=%s%s";
    
    if ((StringUtils.isNotBlank(resumeUrl)) && (!StringUtils.startsWithIgnoreCase(resumeUrl, "http")))
    {
      resumeUrl = baseUrl + resumeUrl;
    }
    
    String optionalTargetResource = StringUtils.isNotBlank(resumeUrl) ? "&TargetResource=" + URLEncoder.encode(resumeUrl, "UTF-8") : "";
    
    return String.format(changePasswordEndpoint, new Object[] {
      URLEncoder.encode(adapterId, "UTF-8"), optionalTargetResource });
  }
  
  public static String getRecoverUsernameUrl(String baseUrl, String adapterId, String resumeUrl)
    throws IOException
  {
    String passwordRecoveryEndpoint = baseUrl + "/ext/idrecovery/Recover" + "?" + "AdapterId" + "=%s%s";
    
    if ((StringUtils.isNotBlank(resumeUrl)) && (!StringUtils.startsWithIgnoreCase(resumeUrl, "http")))
    {
      resumeUrl = baseUrl + resumeUrl;
    }
    
    String optionalTargetResource = StringUtils.isNotBlank(resumeUrl) ? "&TargetResource=" + URLEncoder.encode(resumeUrl, "UTF-8") : "";
    
    return String.format(passwordRecoveryEndpoint, new Object[] {
      URLEncoder.encode(adapterId, "UTF-8"), optionalTargetResource });
  }
  

  private Map<String, String> getChangePasswordParam()
  {
    Map<String, String> changePasswordParam = new HashMap();
    changePasswordParam.put(CHANGE_PASSWORD, "true");
    
    return changePasswordParam;
  }
  




  public static void promptForPasswordChange(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, AuthnPolicy authnPolicy, String url, String authnMessageKey, boolean isChainedUsernameAvailable, String username, String pwmLocation, String pwmTemplateName, boolean adminAllowsPasswordChanges, String sessionKeyLoginContext)
    throws IOException
  {
    if (StringUtils.isBlank(pwmLocation))
    {
      changePasswordWithForm(req, resp, inParameters, authnPolicy, url, null, authnMessageKey, isChainedUsernameAvailable, username, sessionKeyLoginContext);

    }
    else
    {

      doRedirectOrMessageTemplate(req, resp, inParameters, authnPolicy, pwmLocation, pwmTemplateName, "pwmHeaderMessage", authnMessageKey, "pwmLinkText", adminAllowsPasswordChanges);
    }
  }
  




  private static void changePasswordWithForm(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, AuthnPolicy authnPolicy, String url, List<String> errorMessageKeyList, String authnMessageKey, boolean isChainedUsernameAvailable, String chainedUsername, String sessionKeyLoginContext)
    throws IOException
  {
    String clientId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.oauth.client.id");
    String spAdapterId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.sp.adapter.id");
    String adapterId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.instanceid");
    









    ChangePasswordSessionState state = new ChangePasswordSessionState.Builder().fromHtmlFormAdapter(true).clientId(StringUtils.isNotBlank(clientId) ? clientId : null).sessionKeyLoginContext(sessionKeyLoginContext).chainedUsernameAvailable(isChainedUsernameAvailable).chainedUsername(chainedUsername).authnMessageKey(authnMessageKey).authnPolicy(authnPolicy).passwordExpiring(isResetPendingPassword(req)).spAdapterId(StringUtils.isNotBlank(spAdapterId) ? spAdapterId : null).build();
    state.save(req, resp);
    
    resp.sendRedirect(getChangePasswordUrl(adapterId, url));
  }
  



  private static void doRedirectOrMessageTemplate(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, AuthnPolicy authnPolicy, String redirectUrl, String templateName, String headerMessage, String authnMessageKey, String linkText, boolean adminAllowsPasswordChanges)
    throws IOException
  {
    if ((authnPolicy.allowUserInteraction()) && (adminAllowsPasswordChanges))
    {
      if (StringUtils.isBlank(templateName))
      {
        resp.sendRedirect(redirectUrl);
      }
      else
      {
        String clientId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.oauth.client.id");
        String spAdapterId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.sp.adapter.id");
        
        Map<String, Object> params = new HashMap();
        
        params.put("headerMessage", headerMessage);
        params.put("authnMessageKey", authnMessageKey);
        params.put("redirectUrl", redirectUrl);
        params.put("linkText", linkText);
        params.put(Parameters.CLIENT_ID, clientId);
        params.put("spAdapterId", spAdapterId);
        
        TemplateRendererUtil.render(req, resp, templateName, params);
      }
    }
  }
  

  public void configure(Configuration configuration)
  {
    this.maxConsecutiveFailures = Integer.parseInt(configuration.getFieldValue("Challenge Retries"));
    this.accountLockingService = MgmtFactory.getAccountLockingService().getInstance(getClass().getSimpleName() + configuration.getId());
    
    for (Row row : configuration.getTable("Credential Validators").getRows())
    {
      this.pwdCrdVal.add(row.getFieldValue("Password Credential Validator Instance"));
    }
    
    Field lipField = configuration.getField("Local Identity Profile");
    if (lipField != null)
    {
      this.localIdentityProfileId = lipField.getValue();
    }
    
    if (supportsPasswordReset(this.pwdCrdVal))
    {
      registerPasswordResetHandlers();
    }
    log.info("...supportsPasswordReset:"+supportsPasswordReset(this.pwdCrdVal));
    
    if (supportsPasswordChange(this.pwdCrdVal, this.pwmLocation))
    {
      registerChangePasswordHandlers();
    }
    
    if (supportsUsernameRecovery(configuration, this.pwdCrdVal))
    {
      registerRecoverUsernameHandlers();
    }
    
    if ((configuration.getFieldValue("Session Timeout") != null) && 
      (!configuration.getFieldValue("Session Timeout").equals("")))
    {
      this.sessionTimeout = Integer.valueOf(configuration.getFieldValue("Session Timeout"));
    }
    
    String sessionMaxTimeout = configuration.getFieldValue("Session Max Timeout");
    if (StringUtils.isNotBlank(sessionMaxTimeout))
    {
      this.sessionMaxTimeout = Integer.valueOf(sessionMaxTimeout);
    }
    
    this.loginTemplateName = configuration.getFieldValue("Login Template");
    this.logoutRedirectLocation = configuration.getFieldValue("Logout Redirect");
    this.logoutTemplateName = configuration.getFieldValue("Logout Template");
    this.logoutSubPath = configuration.getFieldValue("Logout Path");
    this.sessionState = configuration.getFieldValue("Session State");
    this.loginChallengeTemplateName = configuration.getFieldValue("Login Challenge Template");
    this.adminAllowsPasswordChanges = configuration.getBooleanFieldValue("Allow Password Changes");
    this.enableRememberUsername = configuration.getBooleanFieldValue("Enable 'Remember My Username'");
    this.allowUsernameEdits = configuration.getBooleanFieldValue("Allow Username Edits During Chaining");
    this.changePasswordEmailNotificationTemplateName = configuration.getFieldValue("Change Password Email Template");
    this.resetType = StringUtils.defaultIfEmpty(configuration.getFieldValue("Password Reset Type"), "NONE");
    if (StringUtils.isBlank(this.changePasswordEmailNotificationTemplateName))
    {
      this.changePasswordEmailNotificationTemplateName = "message-template-end-user-password-change.html";
    }
    

    try
    {
      this.rememberUsernameCookieLifetime = Integer.parseInt(configuration.getFieldValue("'Remember My Username' Lifetime"));
    }
    catch (NumberFormatException ne)
    {
      this.rememberUsernameCookieLifetime = 30;
    }
    
    this.pwmLocation = configuration.getFieldValue("Password Management System");
    this.pwmTemplateName = configuration.getFieldValue("Password Management System Message Template");
    
    this.enablePasswordExpiryNotification = configuration.getBooleanFieldValue("Show Password Expiring Warning");
    this.passwordExpiryTemplateName = configuration.getFieldValue("Expiring Password Warning Template");
    if (StringUtils.isBlank(this.passwordExpiryTemplateName))
    {
      this.passwordExpiryTemplateName = "html.form.password.expiring.notification.template.html";
    }
    


    try
    {
      this.expiringPasswordWarningThreshold = Long.valueOf(Long.parseLong(configuration.getFieldValue("Threshold for Expiring Password Warning")) * 86400000L);
    }
    catch (NumberFormatException localNumberFormatException1) {}
    




    try
    {
      this.expiringPasswordSnoozeInterval = (Integer.parseInt(configuration.getFieldValue("Snooze Interval for Expiring Password Warning")) * 3600);
    }
    catch (NumberFormatException localNumberFormatException2) {}
    




    LogoutHandler logoutHandler = new LogoutHandler(this, this.logoutSubPath);
    logoutHandler.setRedirectDestination(this.logoutRedirectLocation);
    logoutHandler.setTemplateName(this.logoutTemplateName);
    logoutHandler.setDefaultContent("<HTML>You've been logged out of the system.</HTML>");
    
    this.trackAuthenticationTime = configuration.getBooleanFieldValue("Track Authentication Time");
    
    this.config = configuration;
    
    this.SESSION_KEY_LOGIN_CONTEXT = (getClass().getSimpleName() + ":" + this.config.getId() + ":formAdapterLoginContext");
    setSessionTracking();
    

    this.cookieName = HtmlFormIdpAuthnAdapterUtils.getRememberUsernameCookieName(this.config.getId());
  }
  
  private void registerPasswordResetHandlers()
  {
    HandlerRegistry.registerHandler("/pwdreset/Identify", new com.efx.pingfed.adapters.htmlform.pwdreset.servlet.IdentifyServlet());
    HandlerRegistry.registerHandler("/pwdreset/SelectMethod", new com.efx.pingfed.adapters.htmlform.pwdreset.servlet.SelectMethodServlet());
    HandlerRegistry.registerHandler("/pwdreset/SecurityCode", new SecurityCodeServlet());
    HandlerRegistry.registerHandler("/pwdreset/Success", new com.pingidentity.adapters.htmlform.pwdreset.servlet.SuccessServlet());
    HandlerRegistry.registerHandler("/pwdreset/Resume", new ResumeServlet());
    HandlerRegistry.registerHandler("/pwdreset/Error", new ErrorServlet());
    HandlerRegistry.registerHandler("/pwdreset/Reset", new ResetServlet());
    HandlerRegistry.registerHandler("/pwdreset/Unlock", new AccountUnlockServlet());
    HandlerRegistry.registerHandler("/pwdreset/PingID", new com.efx.pingfed.adapters.htmlform.pwdreset.servlet.PingIDServlet());

  }
  
  private void registerChangePasswordHandlers()
  {
    HandlerRegistry.registerHandler("/pwdchange/Identify", new com.pingidentity.adapters.htmlform.pwdchange.servlet.IdentifyServlet());
    HandlerRegistry.registerHandler("/pwdchange/Success", new com.pingidentity.adapters.htmlform.pwdchange.servlet.SuccessServlet());
  }
  
  private void registerRecoverUsernameHandlers()
  {
    HandlerRegistry.registerHandler("/idrecovery/Recover", new RecoverUsernameServlet());
  }
  

  public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req, HttpServletResponse resp, String resumePath)
    throws AuthnAdapterException, IOException
  {
    if (isSessionTracking())
    {

      if ((req == null) && (resp == null) && (resumePath == null))
      {
        return false;
      }
      
      this.sessionStateSupport.removeAttribute(this.SESSION_KEY_AUTHN, req, resp);
    }
    
    return true;
  }
  

  public AuthnAdapterResponse lookupAuthN(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters)
    throws AuthnAdapterException, IOException
  {
    AuthnAdapterResponse authnAdapterResponse = null;
    Map responseAttributeMap = null;
    AuthnAdapterResponse.AUTHN_STATUS responseStatus = null;
    HtmlFormLoginContext loginContext = new HtmlFormLoginContext();
    
    String username = inParameters.get("com.pingidentity.adapter.input.parameter.userid") == null ? null : (String)inParameters.get("com.pingidentity.adapter.input.parameter.userid");
    AuthnPolicy authnPolicy = (AuthnPolicy)inParameters.get("com.pingidentity.adapter.input.parameter.authn.policy");
    String resumeUrl = (String)inParameters.get("com.pingidentity.adapter.input.parameter.resume.path");
    String entityId = (String)inParameters.get("com.pingidentity.adapter.input.parameter.partner.entityid");
    String usernameFromRequest = req.getParameter(USERNAME_FIELD);
    
    boolean isChainedUsernameAvailable = true;
    if ((StringUtils.isBlank(username)) || ((!StringUtils.isBlank(usernameFromRequest)) && (!usernameFromRequest.equals(username)) && (this.allowUsernameEdits)))
    {
      username = usernameFromRequest;
      isChainedUsernameAvailable = false;
    }
    
    String requestedAction = getRequestedAction(inParameters, req, resp);
    if (StringUtils.isNotBlank(requestedAction))
    {
      if (log.isDebugEnabled())
        log.debug("A requested action of '" + requestedAction + "' was found.");
      authnAdapterResponse = new AuthnAdapterResponse();
      authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.ACTION);
      authnAdapterResponse.setAttributeMap(Collections.singletonMap("policy.action", requestedAction));
      return authnAdapterResponse;
    }
    
    handleReturnFromChangePassword(req, resp, inParameters, authnPolicy, resumeUrl);
    
    loginContext = handleLoginForm(req, resp, inParameters, entityId, authnPolicy, resumeUrl, loginContext, username, isChainedUsernameAvailable);
    
    responseAttributeMap = loginContext.getAuthnIds();
    
    if (loginContext.isAlternateAuthnSystem())
    {
      responseStatus = AuthnAdapterResponse.AUTHN_STATUS.ACTION;
      username = loginContext.getUserName();
    }
    else if (resp.isCommitted())
    {
      responseStatus = AuthnAdapterResponse.AUTHN_STATUS.IN_PROGRESS;
    }
    else if ((responseAttributeMap == null) || (responseAttributeMap.isEmpty()))
    {
      responseStatus = AuthnAdapterResponse.AUTHN_STATUS.FAILURE;
    }
    else
    {
      responseStatus = AuthnAdapterResponse.AUTHN_STATUS.SUCCESS;
    }
    
    authnAdapterResponse = new AuthnAdapterResponse();
    authnAdapterResponse.setAuthnStatus(responseStatus);
    authnAdapterResponse.setAttributeMap(responseAttributeMap);
    authnAdapterResponse.setUsername(username);
    
    return authnAdapterResponse;
  }
  
  private void handleReturnFromChangePassword(HttpServletRequest req, HttpServletResponse resp, Map<String, Object> inParameters, AuthnPolicy authnPolicy, String resumeUrl)
    throws IOException
  {
    ChangePasswordSessionState changePasswordSessionState = ChangePasswordSessionState.get(req, resp);
    if (changePasswordSessionState.getAuthnPolicy() != null)
    {


      if (!changePasswordSessionState.isPasswordExpiring())
      {
        challengeWithForm(req, resp, inParameters, authnPolicy, resumeUrl, changePasswordSessionState.getChainedUsername(), changePasswordSessionState.isLoginFailed(), changePasswordSessionState
          .getEntityId(), changePasswordSessionState.getErrorMessageKey(), changePasswordSessionState.getAuthnMessageKey(), changePasswordSessionState.getServerError(), changePasswordSessionState
          .isChainedUsernameAvailable());
      }
      changePasswordSessionState.delete(req, resp);
    }
  }
  
  private String getRequestedAction(Map<String, Object> inParameters, HttpServletRequest req, HttpServletResponse resp)
  {
    Object requestedActionInParam = getRequestedActionFromInParams(inParameters);
    if (requestedActionInParam != null)
    {
      if (log.isDebugEnabled())
        log.debug("Using the query parameter '" + requestedActionInParam + "' for the " + "policy.action" + " attribute.");
      return (String)requestedActionInParam;
    }
    
    if (StringUtils.isNotBlank(this.localIdentityProfileId))
    {
      LocalIdentityProfile lip = MgmtFactory.getLocalIdentityProfileManager().getProfile(this.localIdentityProfileId);
      if (lip != null)
      {
        if (log.isDebugEnabled())
          log.debug("Checking session state for the action attribute.");
        SessionStateSupport sessionStateSupport = new SessionStateSupport();
        Object previousRequestedAction = sessionStateSupport.getAttribute(lip.getPolicyActionStateKey(), req, resp);
        if (previousRequestedAction != null)
        {
          log.debug("Found the action '" + previousRequestedAction + "' to use from the session state.");
          return (String)previousRequestedAction;
        }
      }
      else
      {
        log.debug("No local identity profile with id '" + this.localIdentityProfileId + "' was found. Processing HTML Form normally.");
      }
    }
    
    return null;
  }
  
  private String getRequestedActionFromInParams(Map<String, Object> inParameters)
  {
    return (String)inParameters.get("policy.action");
  }
  

  public IdpAuthnAdapterDescriptor getAdapterDescriptor()
  {
    return new IdpAuthnAdapterDescriptor(this, "Forgot Password HTML Form IdP Adapter", this.httpFormGuiConfiguration.createAttributeContract(), true, this.httpFormGuiConfiguration
      .getGuiDescriptor(), false, 
      VersionUtil.getVersion());
  }
  

  public Map<String, Object> getAdapterInfo()
  {
    return null;
  }
  



  private void setSessionTracking()
  {
    String session = "SESSION";
    String firstActivity = "first-activity";
    String lastActivity = "last-activity";
    
    switch (this.sessionState)
    {
    case "Globally": 
      this.SESSION_KEY_AUTHN = (getClass().getSimpleName() + ":" + session);
      this.SESSION_KEY_FIRST_ACTIVITY = (getClass().getSimpleName() + ":" + firstActivity);
      this.SESSION_KEY_LAST_ACTIVITY = (getClass().getSimpleName() + ":" + lastActivity);
      break;
    case "Per Adapter": 
      this.SESSION_KEY_AUTHN = (getClass().getSimpleName() + ":" + this.config.getId() + ":" + session);
      this.SESSION_KEY_FIRST_ACTIVITY = (getClass().getSimpleName() + ":" + this.config.getId() + ":" + firstActivity);
      this.SESSION_KEY_LAST_ACTIVITY = (getClass().getSimpleName() + ":" + this.config.getId() + ":" + lastActivity);
      break;
    default: 
      this.SESSION_KEY_AUTHN = (getClass().getSimpleName() + ":" + session);
      this.SESSION_KEY_FIRST_ACTIVITY = (getClass().getSimpleName() + ":" + firstActivity);
      this.SESSION_KEY_LAST_ACTIVITY = (getClass().getSimpleName() + ":" + lastActivity);
    }
    
  }
  

  public static boolean supportsPasswordChange(List<String> pcvList, String passwordManagementLocation)
  {
    for (String pcvId : pcvList)
    {
      if (HtmlFormIdpAuthnAdapterUtils.supportsPasswordChange(pcvId, passwordManagementLocation))
      {
        return true;
      }
    }
    
    log.warn("The change password feature is disabled for this HTML form adapter instance because none of the configured password credential validators support password changes or they need to be reconfigured.  Check the log for possible related messages from the password credential validators.");
    


    return false;
  }
  
  public static boolean supportsPasswordReset(List<String> pcvList)
  {
    for (String pcvId : pcvList)
    {
      if (HtmlFormIdpAuthnAdapterUtils.supportsPasswordReset(pcvId))
      {
        return true;
      }
    }
    
    return false;
  }
  
  private static boolean supportsUsernameRecovery(Configuration configuration, List<String> pcvList)
  {
    return supportsUsernameRecovery(configuration.getBooleanFieldValue("Enable Username Recovery"), pcvList);
  }
  
  public static boolean supportsUsernameRecovery(boolean enableUsernameRecovery, List<String> pcvList)
  {
    if (enableUsernameRecovery)
    {
      for (String pcvId : pcvList)
      {
        PasswordCredentialValidator pcv = new PasswordCredentialValidatorAccessor().getPasswordCredentialValidator(pcvId);
        if ((pcv instanceof RecoverableUsername))
        {
          return true;
        }
      }
    }
    return false;
  }
  
  public static boolean isResetTypeNone(Configuration configuration)
  { //@TODO
    //String resetType = StringUtils.defaultIfEmpty(configuration.getFieldValue("Password Reset Type"), "NONE");
	//return isResetTypeNone(resetType);  
    boolean isOTPResetAllowed =Boolean.valueOf(configuration.getFieldValue(HtmlFormGuiConfiguration.FIELD_RESET_TYPE_OTP_NAME));
    boolean isPingIDResetAllowed = Boolean.valueOf(configuration.getFieldValue(HtmlFormGuiConfiguration.RESET_TYPE_PINGID_NAME));
    boolean isSMSResetAllowed = Boolean.valueOf(configuration.getFieldValue(HtmlFormGuiConfiguration.RESET_TYPE_SMS_NAME));
    log.info("...isResetAllowed for OPT, PingId and SMS:"+isOTPResetAllowed+", "+isPingIDResetAllowed+", "+isSMSResetAllowed);
    return  !(isOTPResetAllowed||isPingIDResetAllowed||isSMSResetAllowed);
  }
  
  public static boolean isResetTypeNone(String resetType)
  {
    return resetType.equals("NONE");
  }
  
  private boolean isSessionMaxExpired(HttpServletRequest req, HttpServletResponse resp)
  {
    return (isSessionTracking()) && (this.sessionStateSupport.isSessionExpired(this.SESSION_KEY_FIRST_ACTIVITY, this.sessionMaxTimeout, req, resp));
  }
  
  private boolean isCaptchaEnabledAuthentication(Configuration configuration)
  {
    return configuration.getBooleanFieldValue("CAPTCHA for Authentication");
  }
}
