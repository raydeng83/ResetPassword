package com.efx.pingfed.adapters.htmlform.idp;

import com.pingidentity.access.PasswordCredentialValidatorAccessor;
import com.pingidentity.sdk.password.ChallengeablePasswordCredential;
import com.pingidentity.sdk.password.ChangeablePasswordCredential;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;


public final class HtmlFormIdpAuthnAdapterUtils
{
  public static void addCookie(String name, String value, int maxAge, HttpServletResponse response)
  {
    Cookie cookie = new Cookie(name, value);
    cookie.setMaxAge(maxAge);
    cookie.setPath("/");
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    response.addCookie(cookie);
  }
  




  public static boolean supportsChallengeResponse(String pcvId)
  {
    PasswordCredentialValidator pcv = getPcv(pcvId);
    return pcv instanceof ChallengeablePasswordCredential;
  }
  











  public static boolean supportsPasswordChange(String pcvId, String pwmLocation)
  {
    boolean pwdExists = !StringUtils.isBlank(pwmLocation);
    if (pwdExists) {
      return true;
    }
    


    PasswordCredentialValidator pcv = getPcv(pcvId);
    boolean pcvAllowsPasswordChange = pcv instanceof ChangeablePasswordCredential;
    boolean ldapsEnabled = false;
    if (pcvAllowsPasswordChange)
    {
      ldapsEnabled = ((ChangeablePasswordCredential)pcv).isPasswordChangeable();
    }
    
    return (pcvAllowsPasswordChange) && (ldapsEnabled);
  }
  





  public static boolean supportsPasswordReset(String pcvId)
  {
    boolean ldapsEnabled = false;
    PasswordCredentialValidator pcv = getPcv(pcvId);
    boolean pcvAllowsPasswordReset = pcv instanceof ResettablePasswordCredential;
    if (pcvAllowsPasswordReset)
    {
      ldapsEnabled = ((ResettablePasswordCredential)pcv).isPasswordResettable();
    }
    return (pcvAllowsPasswordReset) && (ldapsEnabled);
  }
  




  public static String getRememberUsernameCookieName(String adapterId)
  {
    return "pf-hfa-" + adapterId + "-rmu";
  }
  




  static PasswordCredentialValidator getPcv(String pcvId)
  {
    return new PasswordCredentialValidatorAccessor().getPasswordCredentialValidator(pcvId);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\idp\HtmlFormIdpAuthnAdapterUtils.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */