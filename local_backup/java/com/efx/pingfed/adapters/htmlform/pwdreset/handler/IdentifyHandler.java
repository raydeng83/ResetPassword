package com.efx.pingfed.adapters.htmlform.pwdreset.handler;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.model.GeneratedCode;
import com.pingidentity.adapters.htmlform.pwdreset.model.IdentifyForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.IdentifyResult;
import com.efx.pingfed.adapters.htmlform.pwdreset.util.CodeGenerationUtil;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import com.pingidentity.email.util.NotificationSupportHelper;
import com.pingidentity.locale.LocaleUtil;
import com.pingidentity.pf.sms.SmsSettings;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import com.pingidentity.sms.helper.SmsHelper;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sourceid.common.IDGenerator;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.domain.NotificationSettings;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.NotificationMgr;
import org.sourceid.token.PFInternalTokenGenerator;
import org.sourceid.token.jwt.JwtTokenGeneratorImpl;
import org.sourceid.token.jwt.PFInternalTokenException;
import org.sourceid.token.jwt.PFResetPasswordtoJwtTranslator;
import org.sourceid.util.log.AttributeMap;
import org.sourceid.websso.servlet.reqparam.InvalidRequestParameterException;

public class IdentifyHandler
  extends BaseHandler
{
  private static final Logger logger = LogManager.getLogger(IdentifyHandler.class);
  
  private PFInternalTokenGenerator pfInternalTokenGenerator = new JwtTokenGeneratorImpl(new PFResetPasswordtoJwtTranslator());
  
  public IdentifyHandler(PasswordManagementConfiguration configuration) {
    super(configuration);
  }
  
  public IdentifyResult validateUsername(IdentifyForm identifyForm, HttpServletRequest request, HttpServletResponse response) {
    boolean isUsernameRecovery = (request.getParameter("pf.usernamerecovery") != null) && ("clicked".equals(request.getParameter("pf.usernamerecovery")));
    if (isUsernameRecovery)
    {
      return IdentifyResult.RecoverUsername;
    }
    if (!identifyForm.isSubmit()) {
      logger.debug("Form was not submitted");
      return IdentifyResult.Cancel;
    }
    
    if ((identifyForm.getUsername() == null) || (identifyForm.getUsername().isEmpty())) {
      logger.debug("No Username found in the form data");
      return IdentifyResult.NoUsername;
    }
    
    AttributeMap userAttributes = null;
    String selectedPcvId = null;
    

    for (String pcvId : this.configuration.getPcvIds())
    {
      try
      {
        userAttributes = getAttributes(identifyForm.getUsername(), pcvId);
        
        if (userAttributes != null)
        {
          selectedPcvId = pcvId;
          break;
        }
      }
      catch (Exception e)
      {
        logger.error("Error retrieving user attributes. " + e.getMessage());
        logger.debug(e);
        return null;
      }
    }
    
    GeneratedCode gc = null;
    String referenceId = null;
    if (("OTL".equals(this.configuration.getResetType())) && (userAttributes != null))
    {



      String adapterId = request.getParameter("AdapterId");
      if (adapterId == null)
      {
        adapterId = request.getParameter("adapterId");
      }
      
      String code = adapterId + ":" + selectedPcvId + ":" + IDGenerator.rndAlphaNumeric(22);
      

      Map<String, AttributeValue> attrs = new HashMap();
      

      attrs.put("prCodeMapCode", new AttributeValue(code));
      attrs.put("prUsername", new AttributeValue(identifyForm.getUsername()));
      attrs.put("pcvId", new AttributeValue(selectedPcvId));
      attrs.put("adapterId", new AttributeValue(adapterId));
      attrs.put("prEnableRememberUsername", new AttributeValue(request.getParameter("prEnableRememberUsername")));
      attrs.put("prExpTime", new AttributeValue(String.valueOf(DateUtils.addMinutes(new Date(), this.configuration.getExpirationMinutes()).getTime())));
      
      try
      {
        referenceId = this.pfInternalTokenGenerator.encrypt(attrs);
      }
      catch (PFInternalTokenException e)
      {
        throw new InvalidRequestParameterException(e.getMessage());
      }
      
    }
    else
    {
      gc = CodeGenerationUtil.getGeneratedCode(this.configuration);
      


      this.sessionUtil.add("prCodeMap", gc.getAttributeMap(), request, response);
      this.sessionUtil.add("prUsername", identifyForm.getUsername(), request, response);
      this.sessionUtil.add("prReferrer", identifyForm.getTargetResource(), request, response);
      this.sessionUtil.add("pcvId", selectedPcvId, request, response);
      String adapterIdQueryParam = request.getParameter("AdapterId");
      if (adapterIdQueryParam == null)
      {
        adapterIdQueryParam = request.getParameter("adapterId");
      }
      this.sessionUtil.add("adapterId", adapterIdQueryParam, request, response);
      this.sessionUtil.add("prEnableRememberUsername", request.getParameter("prEnableRememberUsername"), request, response);
    }
    
    if (userAttributes == null)
    {
      logger.debug("Attributes not found for user: " + identifyForm.getUsername());
      return IdentifyResult.UserNotFound;
    }
    
    Locale locale = LocaleUtil.getUserLocale(request);
    
    return doReset(identifyForm, userAttributes, gc, referenceId, selectedPcvId, locale);
  }
  
  private IdentifyResult doReset(IdentifyForm identifyForm, AttributeMap userAttributes, GeneratedCode generatedCode, String referenceId, String pcvId, Locale locale)
  {
    switch (this.configuration.getResetType())
    {
    case "OTL": 
      return sendOneTimeLink(identifyForm, userAttributes, referenceId, pcvId, locale);
    case "OTP": 
      return sendOneTimePassword(identifyForm, userAttributes, generatedCode, pcvId, locale);
    case "PingID": 
      return IdentifyResult.PingID;
    case "SMS": 
      return sendTextMesage(identifyForm, userAttributes, generatedCode, pcvId, locale);
    }
    return IdentifyResult.Error;
  }
  

  private IdentifyResult sendOneTimePassword(IdentifyForm identifyForm, AttributeMap userAttributes, GeneratedCode generatedCode, String pcvId, Locale locale)
  {
    logger.debug("Starting Reset flow using OTP");
    
    ResettablePasswordCredential pcv = getPcv(pcvId);
    String email = userAttributes.getSingleValue(pcv.getMailAttribute());
    if ((email != null) && (!email.isEmpty()))
    {
      String name = userAttributes.getSingleValue(pcv.getNameAttribute());
      if ((name == null) || (name.isEmpty())) {
        name = identifyForm.getUsername();
      }
      
      boolean isEmailVerified = this.configuration.isRequireVerifiedEmail() ? Boolean.valueOf(userAttributes.getSingleValue(pcv.getMailVerifiedAttribute())).booleanValue() : true;
      
      if (isEmailVerified)
      {
        NotificationSupportHelper notificationSupportHelper = new NotificationSupportHelper();
        notificationSupportHelper.sendPasswordResetCode(email, name, generatedCode.getCode(), this.configuration
          .getAdapterId(), pcvId, locale);
        
        logger.debug("Email sent to " + identifyForm.getUsername() + " at " + email);
        return IdentifyResult.CodeSent;
      }
      

      logger.error("Email was not sent to '" + identifyForm.getUsername() + "' as '" + email + "' is not verified.");
      return IdentifyResult.EmailUnverifiedCodeNotSent;
    }
    


    logger.error("No email address found in directory for user: " + identifyForm.getUsername());
    return IdentifyResult.NoEmailAddress;
  }
  


  private IdentifyResult sendOneTimeLink(IdentifyForm identifyForm, AttributeMap userAttributes, String referenceId, String pcvId, Locale locale)
  {
    logger.debug("Starting Reset flow using OTL");
    ResettablePasswordCredential pcv = getPcv(pcvId);
    
    String email = userAttributes.getSingleValue(pcv.getMailAttribute());
    
    if ((email != null) && (!email.isEmpty())) {
      String name = userAttributes.getSingleValue(pcv.getNameAttribute());
      if ((name == null) || (name.isEmpty())) {
        name = identifyForm.getUsername();
      }
      
      try
      {
        boolean isEmailVerified = this.configuration.isRequireVerifiedEmail() ? Boolean.valueOf(userAttributes.getSingleValue(pcv.getMailVerifiedAttribute())).booleanValue() : true;
        
        if (isEmailVerified)
        {
          NotificationSupportHelper notificationSupportHelper = new NotificationSupportHelper();
          notificationSupportHelper.sendPasswordResetOneTimeLink(email, name, referenceId, "/ext/pwdreset/Resume", this.configuration
            .getAdapterId(), pcvId, locale);
          logger.debug("Email sent successfully to " + identifyForm.getUsername() + " at " + email);
          return IdentifyResult.LinkSent;
        }
        

        logger.error("Email was not sent to '" + identifyForm.getUsername() + "' as '" + email + "' is not verified.");
        return IdentifyResult.EmailUnverifiedLinkNotSent;

      }
      catch (Exception e)
      {
        logger.error("Error occurred while sending password reset link", e);
        return IdentifyResult.Error;
      }
    }
    
    logger.error("No email address found in directory for user: " + identifyForm.getUsername());
    return IdentifyResult.NoEmailAddress;
  }
  


  private IdentifyResult sendTextMesage(IdentifyForm identifyForm, AttributeMap userAttributes, GeneratedCode generatedCode, String pcvId, Locale locale)
  {
    logger.debug("Starting Reset flow using SMS");
    
    ResettablePasswordCredential pcv = getPcv(pcvId);
    String toNumber = userAttributes.getSingleValue(pcv.getSmsAttribute());
    if ((toNumber != null) && (!toNumber.isEmpty()) && (generatedCode != null) && 
      (StringUtils.isNotEmpty(generatedCode.getCode())))
    {

      NotificationSettings settings = MgmtFactory.getNotificationMgr().getNotificationSettings();
      SmsSettings smsInfo = new SmsSettings(settings.getSmsAccountId(), settings.getSmsAuthToken(), settings.getSmsFromNumber());
      SmsHelper smsHelper = new SmsHelper(smsInfo);
      boolean smsResult = smsHelper.sendPasswordResetCode(generatedCode.getCode(), toNumber, locale);
      
      if (smsResult)
      {
        logger.debug("SMS sent successfully to: " + identifyForm.getUsername() + " at " + toNumber);
        return IdentifyResult.SmsSent;
      }
      
      logger.debug("SMS not sent successfully to: " + identifyForm.getUsername() + " at " + toNumber);
      return IdentifyResult.SmsNotSent;
    }
    

    logger.debug("No mobile phone found for user: " + identifyForm.getUsername());
    return IdentifyResult.NoMobilePhone;
  }
}


