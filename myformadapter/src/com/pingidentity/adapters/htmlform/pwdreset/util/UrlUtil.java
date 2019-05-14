package com.pingidentity.adapters.htmlform.pwdreset.util;

import javax.servlet.http.HttpServletRequest;



public class UrlUtil
{
  private String contextPath;
  
  public UrlUtil(HttpServletRequest request)
  {
    this.contextPath = request.getContextPath();
  }
  
  public String buildPingIdUrl() {
    return getContextPath() + "/ext/pwdreset/PingID";
  }
  
  public String buildSecurityCodeUrl() {
    return getContextPath() + "/ext/pwdreset/SecurityCode";
  }
  
  public String buildSuccessUrl(String message) {
    if ((message != null) && 
      (!message.isEmpty())) {
      return getContextPath() + "/ext/pwdreset/Success" + "?message=" + message;
    }
    
    return getContextPath() + "/ext/pwdreset/Success";
  }
  
  public String buildErrorUrl(String message) {
    if ((message != null) && 
      (!message.isEmpty())) {
      return getContextPath() + "/ext/pwdreset/Error" + "?message=" + message;
    }
    
    return getContextPath() + "/ext/pwdreset/Error";
  }
  
  public String buildResetUrl() {
    return getContextPath() + "/ext/pwdreset/Reset";
  }
  
  public String buildUnlockSuccessUrl()
  {
    return getContextPath() + "/ext/pwdreset/Unlock";
  }
  
  public String buildPingAuthReturnUrl() {
    return getContextPath() + "/ext/pwdreset/PingID";
  }
  
  public String buildCancelUrl(String referrer) {
    return buildCancelUrl(referrer, "forgot-password-error.cancel");
  }
  
  public String buildCancelUrl(String referrer, String defaultMessage) {
    if ((referrer != null) && 
      (referrer.startsWith("http"))) {
      return referrer;
    }
    
    return buildErrorUrl(defaultMessage);
  }
  
  private String getContextPath() {
    return this.contextPath;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdrese\\util\UrlUtil.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */