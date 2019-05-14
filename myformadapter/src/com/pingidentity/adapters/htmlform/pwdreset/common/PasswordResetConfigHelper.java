package com.pingidentity.adapters.htmlform.pwdreset.common;

import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter;
import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapterUtils;
import com.pingidentity.sdk.account.AccountUnlockablePasswordCredential;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.domain.IdpAuthnAdapterInstance;
import org.sourceid.saml20.domain.mgmt.IdpAdapterManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.PasswordCredentialValidatorManager;
import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;

public final class PasswordResetConfigHelper
{
  private static final Log logger = LogFactory.getLog(PasswordResetConfigHelper.class);

  public static PasswordManagementConfiguration get(String adapterId)
  {
    return createPasswordManagementConfiguration(adapterId);
  }
  
  private static PasswordManagementConfiguration createPasswordManagementConfiguration(String adapterId)
  {
    IdpAuthnAdapterInstance instance = (IdpAuthnAdapterInstance)MgmtFactory.getIdpAdapterManager().getInstance(adapterId);
    
    if (instance == null)
    {
      throw new IllegalArgumentException("Adapter ID " + adapterId + " does not exist");
    }
    
    PasswordManagementConfiguration pwdConfig = new PasswordManagementConfiguration(adapterId);
    
    Configuration configuration = instance.getCompositeConfiguration();
    pwdConfig.setUsernameTemplate(StringUtils.defaultIfEmpty(configuration.getFieldValue("Password Reset Username Template"), "forgot-password.html"));
    pwdConfig.setCodeTemplate(StringUtils.defaultIfEmpty(configuration.getFieldValue("Password Reset Code Template"), "forgot-password-resume.html"));
    pwdConfig.setChangeTemplate(StringUtils.defaultIfEmpty(configuration.getFieldValue("Password Reset Template"), "forgot-password-change.html"));
    pwdConfig.setErrorTemplate(StringUtils.defaultIfEmpty(configuration.getFieldValue("Password Reset Error Template"), "forgot-password-error.html"));
    pwdConfig.setSuccessTemplate(StringUtils.defaultIfEmpty(configuration.getFieldValue("Password Reset Success Template"), "forgot-password-success.html"));
    pwdConfig.setResetType(StringUtils.defaultIfEmpty(configuration.getFieldValue("Password Reset Type"), "NONE"));
    pwdConfig.setCodeNumberOfCharacters(NumberUtils.toInt(configuration.getFieldValue("OTP Length"), NumberUtils.toInt("8")));
    pwdConfig.setExpirationMinutes(NumberUtils.toInt(configuration.getFieldValue("OTP Time to Live"), NumberUtils.toInt("10")));
    pwdConfig.setNumInvalidAttempts(NumberUtils.toInt(configuration.getFieldValue("Challenge Retries"), NumberUtils.toInt("3")));
    pwdConfig.setEnableRememberMyUsername(configuration.getBooleanFieldValue("Enable 'Remember My Username'"));
    pwdConfig.setRememberMyUsernameCookieName(HtmlFormIdpAuthnAdapterUtils.getRememberUsernameCookieName(configuration.getId()));
    pwdConfig.setEnableCaptcha(configuration.getBooleanFieldValue("CAPTCHA for Password Reset"));
    pwdConfig.setRequireVerifiedEmail(configuration.getBooleanFieldValue("Require Verified Email"));
    
    int rememberUsernameCookieLifetime = HtmlFormIdpAuthnAdapter.getRememberUsernameCookieLifetime(NumberUtils.toInt(configuration.getFieldValue("'Remember My Username' Lifetime"), Integer.parseInt("30")));
    pwdConfig.setRememberMyUsernameCookieLifetime(rememberUsernameCookieLifetime);
    
    boolean enableAccountUnlock = configuration.getBooleanFieldValue("Account Unlock");
    pwdConfig.setEnableAccountUnlock(enableAccountUnlock);
    pwdConfig.setUnlockTemplate(StringUtils.defaultIfEmpty(configuration.getFieldValue("Account Unlock Template"), "account-unlock.html"));
    
    List<String> pcvIds = new ArrayList();
    
    for (Row row : configuration.getTable("Credential Validators").getRows())
    {
      String pcvId = row.getFieldValue("Password Credential Validator Instance");
      PasswordCredentialValidator pcv = MgmtFactory.getCredentialValidatorManager().getValidator(pcvId);
      boolean resettablePcv = pcv instanceof ResettablePasswordCredential;
      boolean unlockable = pcv instanceof AccountUnlockablePasswordCredential;
      if ((resettablePcv) && (((ResettablePasswordCredential)pcv).isPasswordResettable()))
      {
        pcvIds.add(pcvId);
        if ((enableAccountUnlock) && (unlockable))
        {

          ((AccountUnlockablePasswordCredential)pcv).isAccountUnlockable();
        }
      }
    }
    
    pwdConfig.setPcvIds(pcvIds);
    

    byte[] pingidPropertiesBytes = configuration.getFileFieldValueAsByteArray("PingID Properties");
    Properties pingidProperties = new Properties();
    try
    {
      if ((pingidPropertiesBytes != null) && (pingidPropertiesBytes.length > 0))
      {
        pingidProperties.load(new ByteArrayInputStream(pingidPropertiesBytes));
        if (!pingidProperties.isEmpty())
        {
          pwdConfig.setPingIdBase64Key(pingidProperties.getProperty("use_base64_key"));
          pwdConfig.setPingIdToken(pingidProperties.getProperty("token"));
          pwdConfig.setPingIdOrgAlias(pingidProperties.getProperty("org_alias"));
          pwdConfig.setPingIdAdminUrl(pingidProperties.getProperty("admin_url"));
          pwdConfig.setPingIdAuthenticatorUrl(pingidProperties.getProperty("authenticator_url"));
        }
      }
    }
    catch (IOException ioe)
    {
      logger.error("An error has occurred when loading PingID configuration : " + ioe.getMessage());
      logger.debug(ioe);
    }
    
    return pwdConfig;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\common\PasswordResetConfigHelper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */