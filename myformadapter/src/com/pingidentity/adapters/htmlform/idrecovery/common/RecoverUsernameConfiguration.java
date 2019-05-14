package com.pingidentity.adapters.htmlform.idrecovery.common;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;


public class RecoverUsernameConfiguration
  implements Serializable
{
  private static final long serialVersionUID = -7615222479510256176L;
  private String adapterId;
  private List<String> pcvIds = new ArrayList();
  
  private boolean enableUsernameRecovery = false;
  private boolean requireVerifiedEmail = false;
  private String usernameRecoveryTemplate = "";
  private String usernameRecoveryInfoTemplate = "";
  private String usernameRecoveryEmailTemplate = "";
  private boolean enableCaptcha = false;
  private boolean enablePasswordRecovery = false;
  
  public RecoverUsernameConfiguration(String adapterId)
  {
    this.adapterId = adapterId;
  }
  
  public String getAdapterId()
  {
    return this.adapterId;
  }
  
  public List<String> getPcvIds()
  {
    return this.pcvIds;
  }
  
  public void setPcvIds(List<String> pcvIds)
  {
    this.pcvIds = pcvIds;
  }
  
  public boolean isEnableUsernameRecovery()
  {
    return this.enableUsernameRecovery;
  }
  
  public void setEnableUsernameRecovery(boolean enableUsernameRecovery)
  {
    this.enableUsernameRecovery = enableUsernameRecovery;
  }
  
  public boolean isRequireVerifiedEmail()
  {
    return this.requireVerifiedEmail;
  }
  
  public void setRequireVerifiedEmail(boolean requireVerifiedEmail)
  {
    this.requireVerifiedEmail = requireVerifiedEmail;
  }
  
  public String getUsernameRecoveryTemplate()
  {
    return this.usernameRecoveryTemplate;
  }
  
  public void setUsernameRecoveryTemplate(String usernameRecoveryTemplate)
  {
    this.usernameRecoveryTemplate = usernameRecoveryTemplate;
  }
  
  public String getUsernameRecoveryInfoTemplate()
  {
    return this.usernameRecoveryInfoTemplate;
  }
  
  public void setUsernameRecoveryInfoTemplate(String usernameRecoveryInfoTemplate)
  {
    this.usernameRecoveryInfoTemplate = usernameRecoveryInfoTemplate;
  }
  
  public String getUsernameRecoveryEmailTemplate()
  {
    return this.usernameRecoveryEmailTemplate;
  }
  
  public void setUsernameRecoveryEmailTemplate(String usernameRecoveryEmailTemplate)
  {
    this.usernameRecoveryEmailTemplate = usernameRecoveryEmailTemplate;
  }
  
  public boolean isEnablePasswordRecovery()
  {
    return this.enablePasswordRecovery;
  }
  
  public void setEnablePasswordRecovery(boolean enablePasswordRecovery)
  {
    this.enablePasswordRecovery = enablePasswordRecovery;
  }
  
  public boolean isEnableCaptcha()
  {
    return this.enableCaptcha;
  }
  
  public void setEnableCaptcha(boolean enableCaptcha)
  {
    this.enableCaptcha = enableCaptcha;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\idrecovery\common\RecoverUsernameConfiguration.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */