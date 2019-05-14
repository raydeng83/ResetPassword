package com.pingidentity.adapters.htmlform.pwdreset.handler;

import com.pingidentity.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.model.ResetForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.BaseResult;
import com.pingidentity.adapters.htmlform.pwdreset.type.ResetResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import com.pingidentity.email.util.NotificationSupportHelper;
import com.pingidentity.locale.LocaleUtil;
import com.pingidentity.sdk.password.PasswordResetException;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.Util;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.domain.LDAPUsernamePasswordCredentialValidator;
import org.sourceid.saml20.service.AssertionReplayPreventionService;
import org.sourceid.saml20.service.BearerAssertionReplayPreventionServiceException;
import org.sourceid.saml20.state.StateMgmtFactory;
import org.sourceid.util.log.AttributeMap;





public class ResetHandler
  extends BaseHandler
{
  private static Log logger = LogFactory.getLog(ResetHandler.class);
  
  public ResetHandler(PasswordManagementConfiguration configuration)
  {
    super(configuration);
  }
  
  public ResetResult resetPassword(ResetForm resetForm, HttpServletRequest request, HttpServletResponse response) throws PasswordResetException
  {
    if (!resetForm.isSubmit()) {
      logger.debug("Form was not submitted");
      return ResetResult.Cancel;
    }
    
    String username = resetForm.getUsername();
    

    if (StringUtils.isEmpty(resetForm.getNewPassword())) {
      logger.debug("No New Password was found in the form data");
      increaseAttemptCount(username, request, response);
      return ResetResult.NoNewPassword;
    }
    if (StringUtils.isEmpty(resetForm.getConfirmPassword())) {
      logger.debug("No Confirm Password was found in the form data");
      increaseAttemptCount(username, request, response);
      return ResetResult.NoConfirmPassword;
    }
    if (!resetForm.getNewPassword().equals(resetForm.getConfirmPassword())) {
      logger.debug("New and Confirm Passwords do not match");
      increaseAttemptCount(username, request, response);
      return ResetResult.PasswordMismatch;
    }
    
    AttributeMap userAttributes = getStoredCode(request, response);
    
    BaseResult expiryResult = handleExpiredRequest(userAttributes);
    if (BaseResult.CodeExpired.equals(expiryResult))
    {
      return ResetResult.Expired;
    }
    
    String pcvId = (String)this.sessionUtil.get("pcvId", request, response);
    


    ResetResult result = resetPassword(username, resetForm.getNewPassword(), pcvId);
    
    Locale locale = LocaleUtil.getUserLocale(request);
    
    if (ResetResult.Success.equals(result))
    {
      if ("OTL".equals(this.configuration.getResetType()))
      {
        addToReplayPrevention(userAttributes.getSingleValue("prCodeMapCode"), new Date(Long.parseLong(((AttributeValue)userAttributes.get("prExpTime")).getValue())), username);
      }
      sendCompletionNotice(resetForm, "Success", pcvId, locale);
    }
    else if (!ResetResult.PasswordConstraintViolation.equals(result))
    {
      sendCompletionNotice(resetForm, "Failed", pcvId, locale);
    }
    
    return result;
  }
  











  private ResetResult resetPassword(String username, String password, String pcvId)
    throws PasswordResetException
  {
    ResettablePasswordCredential pcv = null;
    try {
      pcv = getPcv(pcvId);
      pcv.resetPassword(username, password);
      return ResetResult.Success;
    } catch (Exception e) {
      if ((e instanceof PasswordResetException))
      {
        if (((PasswordResetException)e).isRecoverable())
        {
          if ((pcv instanceof LDAPUsernamePasswordCredentialValidator))
          {
            return ResetResult.PasswordConstraintViolation;
          }
          

          throw ((PasswordResetException)e);
        }
      }
      
      logger.error("Error resetting password for: " + username, e); }
    return ResetResult.Error;
  }
  
  private void addToReplayPrevention(String code, Date expirationTime, String username)
    throws PasswordResetException
  {
    try
    {
      Calendar expiration = Util.getUtcCalendar();
      expiration.setTimeInMillis(expirationTime.getTime());
      AssertionReplayPreventionService replaySvc = StateMgmtFactory.getBearerAssertionReplayPreventionSvc();
      
      replaySvc.isReplay(code, expiration);
    }
    catch (BearerAssertionReplayPreventionServiceException e)
    {
      throw new PasswordResetException(false, "Unable to perform replay check on the password reset code: '" + code + "' for username: " + username, e);
    }
  }
  







  private void sendCompletionNotice(ResetForm resetForm, String status, String pcvId, Locale locale)
  {
    ResettablePasswordCredential pcv = getPcv(pcvId);
    AttributeMap userAttributes = getAttributes(resetForm.getUsername(), pcvId);
    String email = null;
    
    if (userAttributes != null)
    {
      email = userAttributes.getSingleValue(pcv.getMailAttribute());
    }
    
    if (!StringUtils.isEmpty(email))
    {
      String name = userAttributes.getSingleValue(pcv.getNameAttribute());
      if (StringUtils.isEmpty(name))
      {
        name = resetForm.getUsername();
      }
      
      if (status != null)
      {
        boolean isEmailVerified = this.configuration.isRequireVerifiedEmail() ? Boolean.valueOf(userAttributes.getSingleValue(pcv.getMailVerifiedAttribute())).booleanValue() : true;
        
        if (isEmailVerified)
        {
          NotificationSupportHelper notificationSupportHelper = new NotificationSupportHelper();
          if (status.equals("Success"))
          {
            notificationSupportHelper.sendPasswordResetComplete(email, name, status, this.configuration.getAdapterId(), pcvId, locale);
          }
          else if (status.equals("Failed"))
          {
            notificationSupportHelper.sendPasswordResetFailed(email, name, this.configuration.getAdapterId(), pcvId, locale);
          }
        }
        else
        {
          logger.error("Could not send completion email; email address found but it is unverified in directory for user: " + resetForm.getUsername());
        }
        
      }
    }
    else
    {
      logger.error("Could not send completion email; no email address found in directory for user: " + resetForm.getUsername());
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\handler\ResetHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */