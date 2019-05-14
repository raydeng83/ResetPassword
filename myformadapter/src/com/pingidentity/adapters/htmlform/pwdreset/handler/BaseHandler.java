package com.pingidentity.adapters.htmlform.pwdreset.handler;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.type.BaseResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.CodeGenerationUtil;
import com.pingidentity.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import com.pingidentity.common.util.TimeUtil;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import java.text.ParseException;
import java.util.Date;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.domain.mgmt.PasswordCredentialValidatorManager;
import org.sourceid.util.log.AttributeMap;





public class BaseHandler
{
  private static Log logger = LogFactory.getLog(BaseHandler.class);
  protected PasswordManagementConfiguration configuration;
  protected SessionStateUtil sessionUtil;
  
  public BaseHandler(PasswordManagementConfiguration configuration)
  {
    this.configuration = configuration;
    this.sessionUtil = new SessionStateUtil();
  }
  
  protected BaseResult validateCode(String username, String securityCode, AttributeMap userAttributes, HttpServletRequest request, HttpServletResponse response) {
    byte[] code = DatatypeConverter.parseBase64Binary(userAttributes.getSingleValue("prCodeMapCode"));
    byte[] salt = DatatypeConverter.parseBase64Binary(userAttributes.getSingleValue("prCodeMapSalt"));
    
    if ((code != null) && (code.length > 0)) {
      if (CodeGenerationUtil.isExpectedPassword(securityCode.toCharArray(), salt, code)) {
        logger.debug("Code Successfully Validated");
        
        return handleExpiredRequest(userAttributes);
      }
      
      logger.debug("Invalid Code");
      increaseAttemptCount(username, request, response);
      if (getAttemptCount(request, response) >= this.configuration.getNumInvalidAttempts())
      {
        logger.debug("Too many invalid attempts");
        return BaseResult.TooManyAttempts;
      }
      return BaseResult.InvalidCode;
    }
    
    logger.error("Code attribute missing");
    PwdResetAuditLogger.setDescription("Code attribute missing");
    return BaseResult.Error;
  }
  
  protected BaseResult handleExpiredRequest(AttributeMap userAttributes)
  {
    boolean isExpired;
    if ("OTL".equals(this.configuration.getResetType()))
    {
      AttributeValue expTimeAttr = (AttributeValue)userAttributes.get("prExpTime");
      if (expTimeAttr == null)
      {
        logger.debug("Unable to obtain expiration time from OTL user attributes.");
        return BaseResult.CodeExpired;
      }
      

      Long expTime = Long.valueOf(expTimeAttr.getValue());
      isExpired = expTime.longValue() < System.currentTimeMillis();

    }
    else
    {
      Date creationTime = getCreationTime(userAttributes);
      isExpired = isExpired(creationTime);
    }
    
    if (isExpired)
    {
      logger.debug("Password Reset request has expired");
      return BaseResult.CodeExpired;
    }
    

    logger.debug("Password Reset request is valid");
    return BaseResult.Success;
  }
  


  Date getCreationTime(AttributeMap userAttributes)
  {
    Date creationTime;

    try
    {
      creationTime = TimeUtil.decodeGeneralizedTime(userAttributes.getSingleValue("prCodeMapTime"));
    }
    catch (ParseException e) {
      logger.error("Error parsing Date for stored expiration, returning expired", e);
      return null;
    }
    return creationTime;
  }
  

  protected boolean isExpired(AttributeMap userAttributes)
  {
    Date createDate = getCreationTime(userAttributes);
    return isExpired(createDate);
  }
  
  protected boolean isExpired(Date createDate)
  {
    Date now = new Date();
    long result = now.getTime() / 60000L - createDate.getTime() / 60000L;
    logger.debug("Number of minutes since token was generated: " + result);
    
    return result > this.configuration.getExpirationMinutes();
  }
  
  protected AttributeMap getStoredCode(HttpServletRequest request, HttpServletResponse response) {
    AttributeMap attrs = (AttributeMap)this.sessionUtil.get("prCodeMap", request, response);
    return attrs;
  }
  
  protected AttributeMap getAttributes(String username, String pcvId) {
    try {
      ResettablePasswordCredential pcv = (ResettablePasswordCredential)MgmtFactory.getCredentialValidatorManager().getValidator(pcvId);
      return pcv.findUser(username);

    }
    catch (Exception e)
    {
      if ((e.getMessage() != null) && (e.getMessage().contains("User not found")))
      {
        logger.debug(e.getMessage());
      }
      else
      {
        logger.error("Error retrieving user attributes. " + e.getMessage());
        logger.debug(e);
      }
    }
    return null;
  }
  

  protected void increaseAttemptCount(String username, HttpServletRequest request, HttpServletResponse response)
  {
    int count = getAttemptCount(request, response);
    count++;
    logger.debug("Number of Invalid attempts for " + username + " is " + count);
    
    this.sessionUtil.remove("prCount", request, response);
    this.sessionUtil.add("prCount", Integer.valueOf(count), request, response);
  }
  
  protected int getAttemptCount(HttpServletRequest request, HttpServletResponse response)
  {
    int count = 0;
    
    Object savedCount = this.sessionUtil.get("prCount", request, response);
    if (savedCount != null) {
      try
      {
        count = ((Integer)savedCount).intValue();
      }
      catch (Exception e) {
        logger.error("Error converting session count to integer", e);
      }
    }
    return count;
  }
  
  protected ResettablePasswordCredential getPcv(String pcvId)
  {
    return (ResettablePasswordCredential)MgmtFactory.getCredentialValidatorManager().getValidator(pcvId);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\handler\BaseHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */