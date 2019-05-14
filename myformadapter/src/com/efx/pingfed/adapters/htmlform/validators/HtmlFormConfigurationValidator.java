package com.efx.pingfed.adapters.htmlform.validators;

import com.efx.pingfed.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter;
import com.pingidentity.sdk.account.AccountUnlockablePasswordCredential;
import com.pingidentity.sdk.password.ChangeablePasswordCredential;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.RecoverableUsername;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import org.apache.commons.lang.StringUtils;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.saml20.domain.CaptchaSettings;
import org.sourceid.saml20.domain.NotificationSettings;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;


public class HtmlFormConfigurationValidator
  implements ConfigurationValidator
{
  private static final int USERNAME_COOKIE_IDLE_MIN = 1;
  private static final int USERNAME_COOKIE_IDLE_MAX = 3650;
  
  public void validate(Configuration configuration)
    throws ValidationException
  {
    List<String> errors = new ArrayList();
    Table table = configuration.getTable("Credential Validators");
    List<Row> rows = table.getRows();
    
    boolean allowPwdChanges = configuration.getBooleanFieldValue("Allow Password Changes");
    boolean hasExternalPwdMgmtSysLink = !StringUtils.isBlank(configuration.getFieldValue("Password Management System"));
    
    if (rows.isEmpty())
    {
      throw new ValidationException("Please add at least one password credential validator.");
    }
    
    if ((allowPwdChanges) && (StringUtils.isBlank(configuration
      .getFieldValue("Change Password Template"))) && (!hasExternalPwdMgmtSysLink))
    {


      errors.add("Either 'Change Password Template' or 'Password Management System' must be specified if 'Allow Password Changes' is enabled.");
    }
    


    if ((!allowPwdChanges) && (!HtmlFormIdpAuthnAdapter.isResetTypeNone(configuration)))
    {
      errors.add("Allow Password Changes must be selected to enable Password Reset.");
    }
    
    String maxIdleStr = configuration.getFieldValue("'Remember My Username' Lifetime");
    if ((configuration.getBooleanFieldValue("Enable 'Remember My Username'")) && 
      (StringUtils.isBlank(maxIdleStr)))
    {
      errors.add("You must specify a 'Remember My Username' Lifetime value");
    }
    
    if (StringUtils.isNotBlank(maxIdleStr))
    {
      String integerErrorMsg = "You must specify a 'Remember My Username' Lifetime integer value between 1 and 3650";
      
      try
      {
        int maxIdle = Integer.parseInt(maxIdleStr);
        if ((maxIdle < 1) || (maxIdle > 3650))
        {
          errors.add(integerErrorMsg);
        }
      }
      catch (NumberFormatException e)
      {
        errors.add(integerErrorMsg);
      }
    }
    



    String sessionIdleTimeoutStr = configuration.getFieldValue("Session Timeout");
    String sessionMaxTimeoutStr = configuration.getFieldValue("Session Max Timeout");
    
    if ((StringUtils.isNotBlank(sessionIdleTimeoutStr)) && (StringUtils.isNotBlank(sessionMaxTimeoutStr)))
    {
      String errMsg = "The Session Timeout value must either be blank or an integer value that is less than or equal to the Session Max Timeout";
      
      try
      {
        int sessionIdleTimeout = Integer.parseInt(sessionIdleTimeoutStr);
        int sessionMaxTimeout = Integer.parseInt(sessionMaxTimeoutStr);
        if (sessionIdleTimeout > sessionMaxTimeout)
        {
          errors.add(errMsg);
        }
      }
      catch (NumberFormatException e)
      {
        errors.add(errMsg);
      }
    }
    
    NotificationSettings notificationSettings = MgmtFactory.getNotificationMgr().getNotificationSettings();
    boolean enablePasswordChangeEmailNotification = configuration.getBooleanFieldValue("Change Password Email Notification");
    boolean isNotificationSettingsPopulated = notificationSettings.isNotificationEmailSettingsPopulated();
    if (enablePasswordChangeEmailNotification)
    {
      if (!allowPwdChanges)
      {
        errors.add("'Change Password Email Notification' cannot be enabled if 'Allow Password Changes' is disabled.");
      }
      
      if (!isNotificationSettingsPopulated)
      {
        errors.add("'Change Password Email Notification' cannot be enabled if mail settings are not configured within Server Settings.");
      }
    }
    
    boolean enableUsernameRecovery = configuration.getBooleanFieldValue("Enable Username Recovery");
    if (enableUsernameRecovery)
    {
      if (!isNotificationSettingsPopulated)
      {
        errors.add("'Enable Username Recovery' cannot be enabled if mail settings are not configured within Server Settings.");
      }
      
      if (StringUtils.isBlank(configuration.getFieldValue("Username Recovery Email Template")))
      {
        errors.add("'Username Recovery Email Template' cannot be blank if 'Enable Username Recovery' is enabled.");
      }
      if (StringUtils.isBlank(configuration.getFieldValue("Username Recovery Info Template")))
      {
        errors.add("'Username Recovery Info Template' cannot be blank if 'Enable Username Recovery' is enabled.");
      }
      if (StringUtils.isBlank(configuration.getFieldValue("Username Recovery Template")))
      {
        errors.add("'Username Recovery Template' cannot be blank if 'Enable Username Recovery' is enabled.");
      }
    }
    
    String thresholdPasswordExpiryNotification = configuration.getFieldValue("Threshold for Expiring Password Warning");
    String passwordExpiryNotificationSnoozeInterval = configuration.getFieldValue("Snooze Interval for Expiring Password Warning");
    boolean isPasswordExpiryNotificationEnabled = configuration.getBooleanFieldValue("Show Password Expiring Warning");
    
    if ((isPasswordExpiryNotificationEnabled) && (!allowPwdChanges))
    {
      errors.add("'Show Password Expiring Warning' cannot be enabled if 'Allow Password Changes' is disabled.");
    }
    

    int thresholdPwdNotification = -1;
    if (StringUtils.isNotBlank(thresholdPasswordExpiryNotification))
    {
      int minThresholdValue = 1;
      thresholdPwdNotification = getInteger(thresholdPasswordExpiryNotification, minThresholdValue);
      if (thresholdPwdNotification == -1)
      {
        String integerErrorMsg = "You must specify an integer value between " + minThresholdValue + " and " + Integer.MAX_VALUE + " for '" + "Threshold for Expiring Password Warning" + "'.";
        

        errors.add(integerErrorMsg);
      }
    }
    
    int delayPwdNotification = -1;
    if (StringUtils.isNotBlank(passwordExpiryNotificationSnoozeInterval))
    {
      int minDelayValue = 0;
      delayPwdNotification = getInteger(passwordExpiryNotificationSnoozeInterval, minDelayValue);
      if (delayPwdNotification == -1)
      {
        String integerErrorMsg = "You must specify an integer value between " + minDelayValue + " and " + 596523 + " for '" + "Snooze Interval for Expiring Password Warning" + "'.";
        
        errors.add(integerErrorMsg);
      }
    }
    
    if ((thresholdPwdNotification != -1) && (delayPwdNotification != -1))
    {
      if (thresholdPwdNotification * 24 < delayPwdNotification)
      {
        String thresholdLessThanDelay = "'Threshold for Expiring Password Warning' duration cannot be less than the 'Snooze Interval for Expiring Password Warning'.";
        
        errors.add(thresholdLessThanDelay);
      }
    }
    



    String pingidBase64Key = null;
    String pingidToken = null;
    String pingidOrgAlias = null;
    
    byte[] pingidPropertiesBytes = configuration.getFileFieldValueAsByteArray("PingID Properties");
    
    if ((pingidPropertiesBytes != null) && (pingidPropertiesBytes.length > 0))
    {
      Properties pingidProperties = new Properties();
      try
      {
        pingidProperties.load(new ByteArrayInputStream(pingidPropertiesBytes));
      }
      catch (IOException io)
      {
        throw new ValidationException(io.getMessage());
      }
      
      if (!pingidProperties.isEmpty())
      {
        pingidBase64Key = pingidProperties.getProperty("use_base64_key");
        if (StringUtils.isEmpty(pingidBase64Key))
        {
          throw new ValidationException("Uploaded file for 'PingID Properties' does not contain the property use_base64_key.");
        }
        pingidToken = pingidProperties.getProperty("token");
        if (StringUtils.isEmpty(pingidToken))
        {
          throw new ValidationException("Uploaded file for 'PingID Properties' does not contain the property token.");
        }
        pingidOrgAlias = pingidProperties.getProperty("org_alias");
        if (StringUtils.isEmpty(pingidOrgAlias))
        {
          throw new ValidationException("Uploaded file for 'PingID Properties' does not contain the property org_alias.");
        }
        
      }
      else
      {
        throw new ValidationException("Uploaded file for 'PingID Properties' does not contain any properties.");
      }
    }
    
    errors.addAll(validatePasswordResetType(configuration, notificationSettings, pingidBase64Key, pingidToken, pingidOrgAlias));
    
    boolean accountUnlock = configuration.getBooleanFieldValue("Account Unlock");
    if ((accountUnlock) && 
      ("NONE".equals(
      getConfigurationValue(configuration, "Password Reset Type", "NONE"))))
    {
      String noPwdRestTypeUnlockAaccount = "A 'Password Reset Type' option (other than NONE) must be selected to enable Account Unlock.";
      

      errors.add(noPwdRestTypeUnlockAaccount);
    }
    
    if ((allowPwdChanges) || (!HtmlFormIdpAuthnAdapter.isResetTypeNone(configuration)) || (enableUsernameRecovery) || (accountUnlock))
    {
      boolean hasChangeablePasswordCredential = false;
      boolean hasResettablePasswordCredential = false;
      boolean hasUnlockablePasswordCredential = false;
      boolean hasRecoverableUsernameCredential = false;
      for (Row row : configuration.getTable("Credential Validators").getRows())
      {
        String pcvId = row.getFieldValue("Password Credential Validator Instance");
        PasswordCredentialValidator pcv = MgmtFactory.getCredentialValidatorManager().getValidator(pcvId);
        if ((pcv instanceof ResettablePasswordCredential))
        {
          hasResettablePasswordCredential = true;
        }
        
        if ((pcv instanceof ChangeablePasswordCredential))
        {
          hasChangeablePasswordCredential = true;
        }
        
        if ((pcv instanceof AccountUnlockablePasswordCredential))
        {
          hasUnlockablePasswordCredential = true;
        }
        
        if ((pcv instanceof RecoverableUsername))
        {
          hasRecoverableUsernameCredential = true;
        }
      }
      if ((allowPwdChanges) && (!hasChangeablePasswordCredential) && (!hasExternalPwdMgmtSysLink))
      {
        errors.add("A password credential validator that supports changing passwords or an external password management system must be configured if 'Allow Password Changes' is enabled.");
      }
      if ((!HtmlFormIdpAuthnAdapter.isResetTypeNone(configuration)) && (!hasResettablePasswordCredential))
      {
        errors.add("A password credential validator that supports resetting passwords must be configured if a 'Password Reset Type' is selected.");
      }
      if ((accountUnlock) && (!hasUnlockablePasswordCredential))
      {
        errors.add("A password credential validator that supports unlocking an account must be configured if a 'Account Unlock' is selected.");
      }
      if ((enableUsernameRecovery) && (!hasRecoverableUsernameCredential))
      {
        errors.add("A password credential validator that supports recovering a username must be configured if a 'Enable Username Recovery' is selected.");
      }
    }
    
    errors.addAll(validateCaptchaEnabledActions(configuration));
    
    if (!errors.isEmpty())
    {
      throw new ValidationException(errors);
    }
  }
  

  private Collection<? extends String> validateCaptchaEnabledActions(Configuration configuration)
  {
    List<String> errors = new ArrayList();
    
    if ((configuration.getBooleanFieldValue("CAPTCHA for Authentication")) || 
      (configuration.getBooleanFieldValue("CAPTCHA for Password Reset")) || 
      (configuration.getBooleanFieldValue("CAPTCHA for Username recovery")) || 
      (configuration.getBooleanFieldValue("CAPTCHA for Password change")))
    {
      CaptchaSettings captchaSettings = MgmtFactory.getCaptchaManager().getCaptchaSettings();
      String secretKey = captchaSettings.getSecretKey();
      String siteKey = captchaSettings.getSiteKey();
      if ((StringUtils.isEmpty(siteKey)) || (StringUtils.isEmpty(secretKey)))
      {
        errors.add("CAPTCHA settings must be configured if CAPTCHA is enabled for any action.");
      }
    }
    
    return errors;
  }
  

  private List<String> validatePasswordResetType(Configuration configuration, NotificationSettings notificationSettings, String pingidBase64Key, String pingidToken, String pingidOrgAlias)
  {
    List<String> errors = new ArrayList();
    switch (getConfigurationValue(configuration, "Password Reset Type", "NONE"))
    {

    case "PingID": 
      if ((StringUtils.isEmpty(pingidBase64Key)) || (StringUtils.isEmpty(pingidToken)) || (StringUtils.isEmpty(pingidOrgAlias)))
      {
        errors.add("The pingid.properties settings file must be provided if Password Reset Type is PingID.");
      }
      

      break;
    case "SMS": 
      String smsAccountId = notificationSettings.getSmsAccountId();
      String smsAuthToken = notificationSettings.getSmsAuthToken();
      String smsFromNumber = notificationSettings.getSmsFromNumber();
      
      if ((StringUtils.isEmpty(smsAccountId)) || (StringUtils.isEmpty(smsAuthToken)) || (StringUtils.isEmpty(smsFromNumber)))
      {
        errors.add("SMS Provider Settings must be configured if Password Reset Type is Text Message.");
      }
      

      break;
    case "OTL": 
      if (!notificationSettings.isNotificationEmailSettingsPopulated())
      {
        errors.add("Mail settings must be configured if Password Reset Type is Email One-Time Link.");
      }
      

      break;
    case "OTP": 
      if (!notificationSettings.isNotificationEmailSettingsPopulated())
      {
        errors.add("Mail settings must be configured if Password Reset Type is Email One-Time Password.");
      }
      
      break;
    }
    
    
    return errors;
  }
  
  private int getInteger(String value, int minValue)
  {
    int intValue = -1;
    try
    {
      intValue = Integer.parseInt(value);
      if ((intValue < minValue) || (intValue > Integer.MAX_VALUE))
      {
        return -1;
      }
    }
    catch (NumberFormatException e)
    {
      return -1;
    }
    return intValue;
  }
  
  private String getConfigurationValue(Configuration configuration, String fieldName, String defaultValue)
  {
    if (!StringUtils.isBlank(configuration.getFieldValue(fieldName)))
    {
      return configuration.getFieldValue(fieldName);
    }
    
    return defaultValue;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\validators\HtmlFormConfigurationValidator.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */