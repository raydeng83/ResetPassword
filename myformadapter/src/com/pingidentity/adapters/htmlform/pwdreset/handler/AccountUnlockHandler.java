package com.pingidentity.adapters.htmlform.pwdreset.handler;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.model.AccountUnlockSuccessForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.ResetResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import com.pingidentity.common.util.LogGuard;
import com.pingidentity.email.util.NotificationSupportHelper;
import com.pingidentity.locale.LocaleUtil;
import com.pingidentity.sdk.account.AccountUnlockablePasswordCredential;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import java.util.Locale;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.PasswordCredentialValidatorManager;
import org.sourceid.util.log.AttributeMap;



public class AccountUnlockHandler
  extends BaseHandler
{
  private static Log logger = LogFactory.getLog(AccountUnlockHandler.class);
  
  public AccountUnlockHandler(PasswordManagementConfiguration configuration)
  {
    super(configuration);
  }
  


  public AccountUnlockSuccessAction action(AccountUnlockSuccessForm form, HttpServletRequest request, HttpServletResponse response)
  {
    if (form.isContinue())
    {
      return AccountUnlockSuccessAction.Continue;
    }
    
    if (form.isReset())
    {
      return AccountUnlockSuccessAction.Reset;
    }
    
    return AccountUnlockSuccessAction.Cancel;
  }
  









  public ResetResult isUserAccountLocked(String username, HttpServletRequest request, HttpServletResponse response)
  {
    String pcvId = (String)this.sessionUtil.get("pcvId", request, response);
    boolean isLocked = false;
    try
    {
      PasswordCredentialValidator pcv = MgmtFactory.getCredentialValidatorManager().getValidator(pcvId);
      if ((pcv instanceof AccountUnlockablePasswordCredential))
      {
        isLocked = ((AccountUnlockablePasswordCredential)pcv).isAccountLocked(username);
      }
    }
    catch (Exception e)
    {
      logger.error("Error while checking for user account status: " + username, e);
      return ResetResult.Error;
    }
    
    if (isLocked)
    {
      return ResetResult.Locked;
    }
    
    return ResetResult.None;
  }
  
  public ResetResult unlockAccount(String username, HttpServletRequest request, HttpServletResponse response)
  {
    String pcvId = (String)this.sessionUtil.get("pcvId", request, response);
    
    try
    {
      PasswordCredentialValidator pcv = MgmtFactory.getCredentialValidatorManager().getValidator(pcvId);
      if ((pcv instanceof AccountUnlockablePasswordCredential))
      {
        boolean unlockSuccess = ((AccountUnlockablePasswordCredential)pcv).unlockAccount(username);
        if (unlockSuccess)
        {
          Locale userLocale = LocaleUtil.getUserLocale(request);
          sendNotice(username, "Success", pcvId, userLocale);
        }
      }
    }
    catch (Exception e)
    {
      logger.error("Error while unlocking the user account: " + username + ". " + e.getMessage());
      logger.debug(e.getStackTrace());
      return ResetResult.Error;
    }
    
    return ResetResult.Success;
  }
  

  private void sendNotice(String username, String status, String pcvId, Locale locale)
  {
    AttributeMap userAttributes = getAttributes(username, pcvId);
    

    if (userAttributes != null)
    {
      ResettablePasswordCredential pcv = getPcv(pcvId);
      String email = userAttributes.getSingleValue(pcv.getMailAttribute());
      
      if (!StringUtils.isEmpty(email))
      {
        String name = userAttributes.getSingleValue(pcv.getNameAttribute());
        if (StringUtils.isEmpty(name))
        {
          name = username;
        }
        
        if (status != null)
        {
          NotificationSupportHelper notificationSupportHelper = new NotificationSupportHelper();
          
          if (status.equals("Success"))
          {
            notificationSupportHelper.sendAccountUnlockComplete(email, name, this.configuration.getAdapterId(), pcvId, locale);
          }
        }
      }
      else
      {
        logger.error("Could not send unlock completion email; no email address found in directory for user: " + LogGuard.encode(username));
      }
    }
    else
    {
      logger.error("No user attributes are found for the user: " + LogGuard.encode(username));
    }
  }
  
  public static enum AccountUnlockSuccessAction
  {
    Continue, 
    Reset, 
    Cancel;
    
    private AccountUnlockSuccessAction() {}
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\handler\AccountUnlockHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */