package com.pingidentity.adapters.htmlform.pwdchange.common;

import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapterUtils;
import com.pingidentity.sdk.password.ChangeablePasswordCredential;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.domain.IdpAuthnAdapterInstance;
import org.sourceid.saml20.domain.mgmt.IdpAdapterManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.PasswordCredentialValidatorManager;


public final class PasswordChangeConfigHelper
{
  public static PasswordChangeConfiguration get(String adapterId)
  {
    return createPasswordChangeConfiguration(adapterId);
  }
  
  private static PasswordChangeConfiguration createPasswordChangeConfiguration(String adapterId)
  {
    IdpAuthnAdapterInstance instance = (IdpAuthnAdapterInstance)MgmtFactory.getIdpAdapterManager().getInstance(adapterId);
    
    if (instance == null)
    {
      throw new IllegalArgumentException("Adapter ID " + adapterId + " does not exist");
    }
    
    PasswordChangeConfiguration pwdConfig = new PasswordChangeConfiguration(adapterId);
    
    Configuration configuration = instance.getCompositeConfiguration();
    
    pwdConfig.setAllowsChangePassword(configuration.getBooleanFieldValue("Allow Password Changes"));
    pwdConfig.setEnableRememberMyUsername(configuration.getBooleanFieldValue("Enable 'Remember My Username'"));
    pwdConfig.setAllowUsernameEdits(configuration.getBooleanFieldValue("Allow Username Edits During Chaining"));
    pwdConfig.setTrackAuthenticationTime(configuration.getBooleanFieldValue("Track Authentication Time"));
    pwdConfig.setEnablePasswordExpiryNotification(configuration.getBooleanFieldValue("Show Password Expiring Warning"));
    pwdConfig.setEnableChangePasswordEmailNotification(configuration.getBooleanFieldValue("Change Password Email Notification"));
    pwdConfig.setEnableUsernameRecovery(configuration.getBooleanFieldValue("Enable Username Recovery"));
    pwdConfig.setCaptchaEnabledPasswordChange(configuration.getBooleanFieldValue("CAPTCHA for Password change"));
    
    pwdConfig.setNumInvalidAttempts(NumberUtils.toInt(configuration.getFieldValue("Challenge Retries"), NumberUtils.toInt("3")));
    pwdConfig.setPwChangeReauthDelay(Integer.parseInt(StringUtils.defaultIfEmpty(configuration.getFieldValue("Post-Password Change Re-Authentication Delay"), "0")));
    
    pwdConfig.setPwmLocation(configuration.getFieldValue("Password Management System"));
    pwdConfig.setChangePasswordTemplateName(StringUtils.defaultIfEmpty(configuration.getFieldValue("Change Password Template"), "html.form.change.password.template.html"));
    pwdConfig.setChangePasswordEmailNotificationTemplateName(StringUtils.defaultIfEmpty(configuration.getFieldValue("Change Password Email Template"), "message-template-end-user-password-change.html"));
    pwdConfig.setChangePasswordMessageTemplateName(configuration.getFieldValue("Change Password Message Template"));
    pwdConfig.setSessionState(StringUtils.defaultIfEmpty(configuration.getFieldValue("Session State"), "None"));
    pwdConfig.setResetType(StringUtils.defaultIfEmpty(configuration.getFieldValue("Password Reset Type"), "NONE"));
    pwdConfig.setLoginTemplateName(configuration.getFieldValue("Login Template"));
    pwdConfig.setPasswordExpiryTemplateName(StringUtils.defaultIfEmpty(configuration.getFieldValue("Expiring Password Warning Template"), "html.form.password.expiring.notification.template.html"));
    pwdConfig.setRememberUsernameCookieLifetime(NumberUtils.toInt(configuration.getFieldValue("'Remember My Username' Lifetime"), Integer.parseInt("30")));
    pwdConfig.setExpiringPasswordWarningThreshold(Long.valueOf(NumberUtils.toLong(configuration.getFieldValue("Threshold for Expiring Password Warning"), 7L) * 86400000L));
    
    List<String> pcvIds = new ArrayList();
    
    for (Row row : configuration.getTable("Credential Validators").getRows())
    {
      String pcvId = row.getFieldValue("Password Credential Validator Instance");
      PasswordCredentialValidator pcv = MgmtFactory.getCredentialValidatorManager().getValidator(pcvId);
      boolean changeablePcv = pcv instanceof ChangeablePasswordCredential;
      if ((changeablePcv) && (((ChangeablePasswordCredential)pcv).isPasswordChangeable()))
      {
        pcvIds.add(pcvId);
      }
    }
    pwdConfig.setPcvIds(pcvIds);
    
    pwdConfig.setCookieName(HtmlFormIdpAuthnAdapterUtils.getRememberUsernameCookieName(adapterId));
    
    return pwdConfig;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\common\PasswordChangeConfigHelper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */