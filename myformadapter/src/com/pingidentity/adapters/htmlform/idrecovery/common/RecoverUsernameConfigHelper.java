package com.pingidentity.adapters.htmlform.idrecovery.common;

import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.RecoverableUsername;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.domain.IdpAuthnAdapterInstance;
import org.sourceid.saml20.domain.mgmt.IdpAdapterManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.PasswordCredentialValidatorManager;

public final class RecoverUsernameConfigHelper
{
  private static final Log logger = LogFactory.getLog(RecoverUsernameConfigHelper.class);
  




  public static RecoverUsernameConfiguration get(String adapterId)
  {
    return createUsernameRecoveryConfiguration(adapterId);
  }
  
  private static RecoverUsernameConfiguration createUsernameRecoveryConfiguration(String adapterId)
  {
    IdpAuthnAdapterInstance instance = (IdpAuthnAdapterInstance)MgmtFactory.getIdpAdapterManager().getInstance(adapterId);
    
    if (instance == null)
    {
      throw new IllegalArgumentException("Adapter ID " + adapterId + " does not exist");
    }
    
    RecoverUsernameConfiguration recoveryConfig = new RecoverUsernameConfiguration(adapterId);
    
    Configuration configuration = instance.getCompositeConfiguration();
    recoveryConfig.setEnableUsernameRecovery(configuration.getBooleanFieldValue("Enable Username Recovery"));
    recoveryConfig.setRequireVerifiedEmail(configuration.getBooleanFieldValue("Require Verified Email"));
    recoveryConfig.setUsernameRecoveryTemplate(StringUtils.defaultIfEmpty(configuration.getFieldValue("Username Recovery Template"), "username.recovery.template.html"));
    recoveryConfig.setUsernameRecoveryInfoTemplate(StringUtils.defaultIfEmpty(configuration.getFieldValue("Username Recovery Info Template"), "username.recovery.info.template.html"));
    recoveryConfig.setUsernameRecoveryEmailTemplate(StringUtils.defaultIfEmpty(configuration.getFieldValue("Username Recovery Email Template"), "message-template-username-recovery.html"));
    recoveryConfig.setEnableCaptcha(configuration.getBooleanFieldValue("CAPTCHA for Username recovery"));
    recoveryConfig.setEnablePasswordRecovery(!HtmlFormIdpAuthnAdapter.isResetTypeNone(configuration));
    
    List<String> pcvIds = new ArrayList();
    
    for (Row row : configuration.getTable("Credential Validators").getRows())
    {
      String pcvId = row.getFieldValue("Password Credential Validator Instance");
      PasswordCredentialValidator pcv = MgmtFactory.getCredentialValidatorManager().getValidator(pcvId);
      boolean recoverableUsername = pcv instanceof RecoverableUsername;
      if (recoverableUsername)
      {
        pcvIds.add(pcvId);
      }
    }
    
    recoveryConfig.setPcvIds(pcvIds);
    
    return recoveryConfig;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\idrecovery\common\RecoverUsernameConfigHelper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */