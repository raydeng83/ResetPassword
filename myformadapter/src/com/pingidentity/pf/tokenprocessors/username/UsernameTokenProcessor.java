package com.pingidentity.pf.tokenprocessors.username;

import com.pingidentity.access.PasswordCredentialValidatorAccessor;
import com.pingidentity.common.security.AccountLockingService;
import com.pingidentity.common.security.LockingService;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.PasswordCredentialValidatorAuthnException;
import com.pingidentity.sdk.password.PasswordValidationException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.VersionUtil;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.FieldList;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.PasswordCredentialValidatorFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TableDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.EnhancedRowValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.saml20.adapter.gui.validation.impl.IntegerValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.service.impl.proxy.LockingServiceFactory;
import org.sourceid.util.log.AttributeMap;
import org.sourceid.websso.AuditLogger;
import org.sourceid.wstrust.model.UsernameToken;
import org.sourceid.wstrust.plugin.TokenProcessingException;
import org.sourceid.wstrust.plugin.process.FailedAuthnException;
import org.sourceid.wstrust.plugin.process.TokenContext;
import org.sourceid.wstrust.plugin.process.TokenProcessor;
import org.sourceid.wstrust.plugin.process.TokenProcessorDescriptor;






















public class UsernameTokenProcessor
  implements TokenProcessor<UsernameToken>
{
  private static class PcvRowValidator
    implements EnhancedRowValidator, Serializable
  {
    private static final long serialVersionUID = 1L;
    
    public void validate(FieldList fieldsInRow)
      throws ValidationException
    {}
    
    public void validate(FieldList fieldsInRow, Configuration configuration)
      throws ValidationException
    {
      List<String> adapters = new ArrayList();
      for (Row row : configuration.getTable("Credential Validators").getRows())
      {
        String pcvName = row.getFieldValue("Password Credential Validator Instance");
        if (adapters.contains(pcvName))
        {
          throw new ValidationException("Password Credential Validator '" + pcvName + "' has already been added");
        }
        
        adapters.add(pcvName);
      }
    }
  }
  
  private static final Log log = LogFactory.getLog(UsernameTokenProcessor.class);
  
  private static final String TP_NAME = "Username Token Processor";
  
  private static final String TP_DESC = "A token processor that validates username tokens against a set of Password Credential Validator instances. The first Credential Validator that successfully validates a token will pass its attributes to this token processor and can be accessed by extending the attribute contract.";
  
  private static final String PCVS_DESCRIPTION = "A list of Credential Validator instances to authenticate Username Tokens. A token is processed in the same order as the selected Credential Validators";
  
  private static final String PCV_DESCRIPTION = "A configured Password Credential Validator instance";
  
  private static final String USERNAME_ATTRIBUTE = "username";
  public static final String MAX_AUTH_ATTEMPTS = String.valueOf(AccountLockingService.getMaxConsecutiveFailures());
  
  public static final String FIELD_RETRIES = "Authentication Attempts";
  
  public static final String DESC_RETRIES = "Max number of failed Authentication Attempts before locking a user account.";
  private LockingService accountLockingService;
  private int maxConsecutiveFailures;
  private final TokenProcessorDescriptor processorDescriptor;
  private final List<String> pcvIds = new LinkedList();
  
  public UsernameTokenProcessor()
  {
    Set<String> attrContract = new HashSet();
    attrContract.add("username");
    GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor("A token processor that validates username tokens against a set of Password Credential Validator instances. The first Credential Validator that successfully validates a token will pass its attributes to this token processor and can be accessed by extending the attribute contract.");
    PasswordCredentialValidatorFieldDescriptor pcvDesc = new PasswordCredentialValidatorFieldDescriptor("Password Credential Validator Instance", "A configured Password Credential Validator instance");
    pcvDesc.addValidator(new RequiredFieldValidator());
    TableDescriptor tableDescriptor = new TableDescriptor("Credential Validators", "A list of Credential Validator instances to authenticate Username Tokens. A token is processed in the same order as the selected Credential Validators");
    tableDescriptor.addRowField(pcvDesc);
    tableDescriptor.addValidator(new PcvRowValidator(null));
    guiDescriptor.addTable(tableDescriptor);
    guiDescriptor.addValidator(new UsernamePcvsConfigValidator());
    
    TextFieldDescriptor retries = new TextFieldDescriptor("Authentication Attempts", "Max number of failed Authentication Attempts before locking a user account.");
    retries.addValidator(new RequiredFieldValidator());
    retries.addValidator(new IntegerValidator(1, 100));
    
    retries.setDefaultValue(MAX_AUTH_ATTEMPTS);
    retries.setDefaultForLegacyConfig(MAX_AUTH_ATTEMPTS);
    guiDescriptor.addField(retries);
    





    this.processorDescriptor = new TokenProcessorDescriptor("Username Token Processor", this, guiDescriptor, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#UsernameToken", attrContract, VersionUtil.getVersion());
    this.processorDescriptor.setSupportsExtendedContract(true);
  }
  

  public TokenProcessorDescriptor getPluginDescriptor()
  {
    return this.processorDescriptor;
  }
  

  public TokenContext processToken(UsernameToken usernameToken)
    throws TokenProcessingException
  {
    String userKey = usernameToken.getRequestIpAddress() + usernameToken.getUsername();
    if (this.accountLockingService.isLocked(userKey, this.maxConsecutiveFailures, AccountLockingService.getLockoutPeriod()))
    {
      throw new FailedAuthnException("Account Locked.");
    }
    
    Throwable firstPcvException = null;
    
    if (this.pcvIds.isEmpty())
    {
      throw new TokenProcessingException("No password credential validators are configured. Rejecting username token.");
    }
    
    for (String pcvId : this.pcvIds)
    {
      AttributeMap attrMap = null;
      
      try
      {
        PasswordCredentialValidatorAccessor pcvAccessor = new PasswordCredentialValidatorAccessor();
        PasswordCredentialValidator pcv = pcvAccessor.getPasswordCredentialValidator(pcvId);
        if (pcv != null)
        {
          attrMap = pcv.processPasswordCredential(usernameToken.getUsername(), usernameToken.getPassword());
        }
      }
      catch (PasswordCredentialValidatorAuthnException e)
      {
        if (log.isInfoEnabled())
        {
          log.info("PCV failed to validate credentials - " + e.getMessage());
        }
        

        continue;

      }
      catch (PasswordValidationException e)
      {
        log.error("PCV failed to process credentials - " + e.getMessage());
        
        if (firstPcvException != null)
        {
          firstPcvException = e;
        }
      }
      continue;
      

      if ((attrMap != null) && (!attrMap.isEmpty()))
      {
        TokenContext tokenContext = new TokenContext();
        
        attrMap.put("username", new AttributeValue(usernameToken.getUsername()));
        tokenContext.setSubjectAttributes(attrMap);
        AuditLogger.setPcvId(pcvId);
        this.accountLockingService.clearFailedLogins(userKey);
        return tokenContext;
      }
    }
    
    if (firstPcvException != null)
    {


      this.accountLockingService.logFailedLogin(userKey);
      throw new FailedAuthnException("Invalid credentials - " + firstPcvException.getMessage());
    }
    
    this.accountLockingService.logFailedLogin(userKey);
    throw new FailedAuthnException("Invalid credentials.");
  }
  

  public void configure(Configuration configuration)
  {
    Table table = configuration.getTable("Credential Validators");
    
    try
    {
      this.maxConsecutiveFailures = Integer.parseInt(configuration.getFieldValue("Authentication Attempts"));
    }
    catch (NumberFormatException ne)
    {
      this.maxConsecutiveFailures = Integer.parseInt(MAX_AUTH_ATTEMPTS);
    }
    
    this.accountLockingService = MgmtFactory.getAccountLockingService().getInstance(getClass().getSimpleName() + configuration.getId());
    this.pcvIds.clear();
    
    if (table != null)
    {
      for (Row row : table.getRows())
      {
        String pcvId = row.getFieldValue("Password Credential Validator Instance");
        this.pcvIds.add(pcvId);
      }
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\tokenprocessor\\username\UsernameTokenProcessor.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */