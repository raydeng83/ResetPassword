package com.efx.pingfed.adapters.htmlform.pwdreset.common;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;


public class PasswordManagementConfiguration
        implements Serializable
{
  private static final long serialVersionUID = -4698855354608219230L;
  private String adapterId;
  private String usernameTemplate;
  private String selectMethodTemplate;
  private String codeTemplate;
  private String changeTemplate;
  private String errorTemplate;
  private String successTemplate;
  private boolean enableAccountUnlock;
  private String unlockTemplate;
  private String resetType;
  private int codeNumberOfCharacters;
  private int expirationMinutes;
  private int numInvalidAttempts;
  private String pingIdBase64Key;
  private String pingIdToken;
  private String pingIdOrgAlias;
  private String pingIdAdminUrl;
  private String pingIdAuthenticatorUrl;
  private boolean enableRememberMyUsername;
  private boolean requireVerifiedEmail;
  private String rememberMyUsernameCookieName;
  private int rememberMyUsernameCookieLifetime;
  private boolean enableCaptcha;
  private List<String> pcvIds = new ArrayList();

  public PasswordManagementConfiguration(String adapterId)
  {
    this.adapterId = adapterId;
    this.selectMethodTemplate = "forgot-password-select-method.html";
  }

  public String getAdapterId() { return this.adapterId; }

  public String getUsernameTemplate() {
    return this.usernameTemplate;
  }

  public void setUsernameTemplate(String usernameTemplate) {
    this.usernameTemplate = usernameTemplate;
  }

  public String getCodeTemplate() {
    return this.codeTemplate;
  }

  public void setCodeTemplate(String codeTemplate) {
    this.codeTemplate = codeTemplate;
  }

  public String getChangeTemplate() {
    return this.changeTemplate;
  }

  public void setChangeTemplate(String changeTemplate) {
    this.changeTemplate = changeTemplate;
  }

  public boolean isEnableAccountUnlock()
  {
    return this.enableAccountUnlock;
  }

  public void setEnableAccountUnlock(boolean enableAccountUnlock)
  {
    this.enableAccountUnlock = enableAccountUnlock;
  }

  public String getUnlockTemplate() {
    return this.unlockTemplate;
  }

  public void setUnlockTemplate(String unlockTemplate) {
    this.unlockTemplate = unlockTemplate;
  }

  public String getErrorTemplate() {
    return this.errorTemplate;
  }

  public void setErrorTemplate(String errorTemplate) {
    this.errorTemplate = errorTemplate;
  }

  public String getSuccessTemplate() {
    return this.successTemplate;
  }

  public void setSuccessTemplate(String successTemplate) {
    this.successTemplate = successTemplate;
  }

  public String getResetType() {
    return this.resetType;
  }

  public void setResetType(String resetType) {
    this.resetType = resetType;
  }

  public int getCodeNumberOfCharacters() {
    return this.codeNumberOfCharacters;
  }

  public void setCodeNumberOfCharacters(int codeNumberOfCharacters) {
    this.codeNumberOfCharacters = codeNumberOfCharacters;
  }

  public int getExpirationMinutes() {
    return this.expirationMinutes;
  }

  public void setExpirationMinutes(int expirationMinutes) {
    this.expirationMinutes = expirationMinutes;
  }

  public int getNumInvalidAttempts() {
    return this.numInvalidAttempts;
  }

  public void setNumInvalidAttempts(int numInvalidAttempts) {
    this.numInvalidAttempts = numInvalidAttempts;
  }

  public String getPingIdBase64Key() {
    return this.pingIdBase64Key;
  }

  public void setPingIdBase64Key(String pingIdBase64Key) {
    this.pingIdBase64Key = pingIdBase64Key;
  }

  public String getPingIdToken() {
    return this.pingIdToken;
  }

  public void setPingIdToken(String pingIdToken) {
    this.pingIdToken = pingIdToken;
  }

  public String getPingIdOrgAlias() {
    return this.pingIdOrgAlias;
  }

  public void setPingIdOrgAlias(String pingIdOrgAlias) {
    this.pingIdOrgAlias = pingIdOrgAlias;
  }

  public String getPingIdAdminUrl() {
    return this.pingIdAdminUrl;
  }

  public void setPingIdAdminUrl(String pingIdAdminUrl) {
    this.pingIdAdminUrl = pingIdAdminUrl;
  }

  public String getPingIdAuthenticatorUrl()
  {
    return this.pingIdAuthenticatorUrl;
  }

  public void setPingIdAuthenticatorUrl(String pingIdAuthenticatorUrl)
  {
    this.pingIdAuthenticatorUrl = pingIdAuthenticatorUrl;
  }

  public List<String> getPcvIds()
  {
    return this.pcvIds;
  }

  public void setPcvIds(List<String> pcvIds)
  {
    this.pcvIds = pcvIds;
  }

  public String getRememberMyUsernameCookieName()
  {
    return this.rememberMyUsernameCookieName;
  }

  public void setRememberMyUsernameCookieName(String rememberMyUsernameCookieName)
  {
    this.rememberMyUsernameCookieName = rememberMyUsernameCookieName;
  }

  public boolean isEnableRememberMyUsername()
  {
    return this.enableRememberMyUsername;
  }

  public void setEnableRememberMyUsername(boolean enableRememberMyUsername)
  {
    this.enableRememberMyUsername = enableRememberMyUsername;
  }

  public int getRememberMyUsernameCookieLifetime()
  {
    return this.rememberMyUsernameCookieLifetime;
  }

  public void setRememberMyUsernameCookieLifetime(int rememberMyUsernameCookieLifetime)
  {
    this.rememberMyUsernameCookieLifetime = rememberMyUsernameCookieLifetime;
  }

  public boolean isRequireVerifiedEmail()
  {
    return this.requireVerifiedEmail;
  }

  public void setRequireVerifiedEmail(boolean requireVerifiedEmail)
  {
    this.requireVerifiedEmail = requireVerifiedEmail;
  }

  public boolean isEnableCaptcha()
  {
    return this.enableCaptcha;
  }

  public void setEnableCaptcha(boolean enableCaptcha)
  {
    this.enableCaptcha = enableCaptcha;
  }

  public String getSelectMethodTemplate() {
    return selectMethodTemplate;
  }

  public void setSelectMethodTemplate(String selectMethodTemplate) {
    this.selectMethodTemplate = selectMethodTemplate;
  }
}


