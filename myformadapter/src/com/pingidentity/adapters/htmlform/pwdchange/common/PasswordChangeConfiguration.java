package com.pingidentity.adapters.htmlform.pwdchange.common;

import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;


public class PasswordChangeConfiguration
  implements Serializable
{
  public String SESSION_KEY_AUTHN = null;
  public String SESSION_KEY_FIRST_ACTIVITY = null;
  public String SESSION_KEY_LAST_ACTIVITY = null;
  
  private static final long serialVersionUID = -4698855354608219230L;
  
  private String adapterId;
  
  private boolean allowsChangePassword;
  
  private boolean enableRememberMyUsername;
  
  private boolean allowUsernameEdits;
  
  private boolean trackAuthenticationTime;
  private boolean enablePasswordExpiryNotification;
  private boolean enableChangePasswordEmailNotification;
  private boolean enableUsernameRecovery;
  private boolean captchaEnabledPasswordChange;
  private int numInvalidAttempts;
  private int pwChangeReauthDelay;
  private int rememberUsernameCookieLifetime;
  private Long expiringPasswordWarningThreshold;
  private String pwmLocation = null;
  private String loginTemplateName = null;
  private String passwordExpiryTemplateName = null;
  private String changePasswordTemplateName = null;
  private String changePasswordEmailNotificationTemplateName = null;
  private String changePasswordMessageTemplateName = null;
  private String sessionState = null;
  private String cookieName = null;
  private String resetType = null;
  
  private List<String> pcvIds = new ArrayList();
  
  public PasswordChangeConfiguration(String adapterId)
  {
    this.adapterId = adapterId;
  }
  
  public String getAdapterId() { return this.adapterId; }
  
  public boolean isEnablePasswordExpiryNotification()
  {
    return this.enablePasswordExpiryNotification;
  }
  
  public void setEnablePasswordExpiryNotification(boolean enablePasswordExpiryNotification)
  {
    this.enablePasswordExpiryNotification = enablePasswordExpiryNotification;
  }
  
  public int getNumInvalidAttempts()
  {
    return this.numInvalidAttempts;
  }
  
  public void setNumInvalidAttempts(int numInvalidAttempts)
  {
    this.numInvalidAttempts = numInvalidAttempts;
  }
  
  public List<String> getPcvIds()
  {
    return this.pcvIds;
  }
  
  public void setPcvIds(List<String> pcvIds)
  {
    this.pcvIds = pcvIds;
  }
  
  public boolean isEnableRememberMyUsername()
  {
    return this.enableRememberMyUsername;
  }
  
  public void setEnableRememberMyUsername(boolean enableRememberMyUsername)
  {
    this.enableRememberMyUsername = enableRememberMyUsername;
  }
  
  public boolean isTrackAuthenticationTime()
  {
    return this.trackAuthenticationTime;
  }
  
  public void setTrackAuthenticationTime(boolean trackAuthenticationTime)
  {
    this.trackAuthenticationTime = trackAuthenticationTime;
  }
  
  public boolean isAllowsChangePassword()
  {
    return this.allowsChangePassword;
  }
  
  public void setAllowsChangePassword(boolean allowsChangePassword)
  {
    this.allowsChangePassword = allowsChangePassword;
  }
  
  public boolean isAllowUsernameEdits()
  {
    return this.allowUsernameEdits;
  }
  
  public void setAllowUsernameEdits(boolean allowUsernameEdits)
  {
    this.allowUsernameEdits = allowUsernameEdits;
  }
  
  public String getChangePasswordTemplateName()
  {
    return this.changePasswordTemplateName;
  }
  
  public void setChangePasswordTemplateName(String changePasswordTemplateName)
  {
    this.changePasswordTemplateName = changePasswordTemplateName;
  }
  
  public boolean isEnableChangePasswordEmailNotification()
  {
    return this.enableChangePasswordEmailNotification;
  }
  
  public void setEnableChangePasswordEmailNotification(boolean enableChangePasswordEmailNotification)
  {
    this.enableChangePasswordEmailNotification = enableChangePasswordEmailNotification;
  }
  
  public String getPwmLocation()
  {
    return this.pwmLocation;
  }
  
  public String getChangePasswordMessageTemplateName()
  {
    return this.changePasswordMessageTemplateName;
  }
  
  public void setChangePasswordMessageTemplateName(String changePasswordMessageTemplateName)
  {
    this.changePasswordMessageTemplateName = changePasswordMessageTemplateName;
  }
  
  public String getChangePasswordEmailNotificationTemplateName()
  {
    return this.changePasswordEmailNotificationTemplateName;
  }
  

  public void setChangePasswordEmailNotificationTemplateName(String changePasswordEmailNotificationTemplateName)
  {
    this.changePasswordEmailNotificationTemplateName = changePasswordEmailNotificationTemplateName;
  }
  

  public int getPwChangeReauthDelay()
  {
    return this.pwChangeReauthDelay;
  }
  
  public void setPwChangeReauthDelay(int pwChangeReauthDelay)
  {
    this.pwChangeReauthDelay = pwChangeReauthDelay;
  }
  
  public void setPwmLocation(String pwmLocation)
  {
    this.pwmLocation = pwmLocation;
  }
  
  public String getLoginTemplateName()
  {
    return this.loginTemplateName;
  }
  
  public void setLoginTemplateName(String loginTemplateName)
  {
    this.loginTemplateName = loginTemplateName;
  }
  
  public String getSessionState()
  {
    return this.sessionState;
  }
  
  public String getCookieName()
  {
    return this.cookieName;
  }
  
  public void setCookieName(String cookieName)
  {
    this.cookieName = cookieName;
  }
  
  public boolean isEnableUsernameRecovery()
  {
    return this.enableUsernameRecovery;
  }
  
  public void setEnableUsernameRecovery(boolean enableUsernameRecovery)
  {
    this.enableUsernameRecovery = enableUsernameRecovery;
  }
  
  public String getResetType()
  {
    return this.resetType;
  }
  
  public void setResetType(String resetType)
  {
    this.resetType = resetType;
  }
  
  public int getRememberUsernameCookieLifetime()
  {
    return this.rememberUsernameCookieLifetime;
  }
  
  public void setRememberUsernameCookieLifetime(int rememberUsernameCookieLifetime)
  {
    this.rememberUsernameCookieLifetime = rememberUsernameCookieLifetime;
  }
  
  public String getPasswordExpiryTemplateName()
  {
    return this.passwordExpiryTemplateName;
  }
  
  public void setPasswordExpiryTemplateName(String passwordExpiryTemplateName)
  {
    this.passwordExpiryTemplateName = passwordExpiryTemplateName;
  }
  
  public boolean isCaptchaEnabledPasswordChange()
  {
    return this.captchaEnabledPasswordChange;
  }
  
  public void setCaptchaEnabledPasswordChange(boolean captchaEnabledPasswordChange)
  {
    this.captchaEnabledPasswordChange = captchaEnabledPasswordChange;
  }
  
  public Long getExpiringPasswordWarningThreshold()
  {
    return this.expiringPasswordWarningThreshold;
  }
  
  public void setExpiringPasswordWarningThreshold(Long expiringPasswordWarningThreshold)
  {
    this.expiringPasswordWarningThreshold = expiringPasswordWarningThreshold;
  }
  
  public void setSessionState(String sessionState)
  {
    this.sessionState = sessionState;
    String session = "SESSION";
    String firstActivity = "first-activity";
    String lastActivity = "last-activity";
    switch (this.sessionState)
    {
    case "Globally": 
      this.SESSION_KEY_AUTHN = (HtmlFormIdpAuthnAdapter.class.getSimpleName() + ":" + session);
      this.SESSION_KEY_FIRST_ACTIVITY = (HtmlFormIdpAuthnAdapter.class.getSimpleName() + ":" + firstActivity);
      this.SESSION_KEY_LAST_ACTIVITY = (HtmlFormIdpAuthnAdapter.class.getSimpleName() + ":" + lastActivity);
      break;
    case "Per Adapter": 
      this.SESSION_KEY_AUTHN = (HtmlFormIdpAuthnAdapter.class.getSimpleName() + ":" + this.adapterId + ":" + session);
      this.SESSION_KEY_FIRST_ACTIVITY = (HtmlFormIdpAuthnAdapter.class.getSimpleName() + ":" + this.adapterId + ":" + firstActivity);
      this.SESSION_KEY_LAST_ACTIVITY = (HtmlFormIdpAuthnAdapter.class.getSimpleName() + ":" + this.adapterId + ":" + lastActivity);
      break;
    default: 
      this.SESSION_KEY_AUTHN = (HtmlFormIdpAuthnAdapter.class.getSimpleName() + ":" + session);
      this.SESSION_KEY_FIRST_ACTIVITY = (HtmlFormIdpAuthnAdapter.class.getSimpleName() + ":" + firstActivity);
      this.SESSION_KEY_LAST_ACTIVITY = (HtmlFormIdpAuthnAdapter.class.getSimpleName() + ":" + lastActivity);
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\common\PasswordChangeConfiguration.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */