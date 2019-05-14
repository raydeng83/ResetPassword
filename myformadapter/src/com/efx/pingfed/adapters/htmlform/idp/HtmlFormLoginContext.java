package com.efx.pingfed.adapters.htmlform.idp;

import com.pingidentity.sdk.password.PasswordCredentialValidatorAuthnException;
import org.sourceid.saml20.domain.mgmt.impl.RadiusAdminUserException;

import java.io.Serializable;
import java.util.Map;


public class HtmlFormLoginContext
  implements Serializable
{
  private static final long serialVersionUID = 20121107L;
  private String pcvId = null;
  private PasswordCredentialValidatorAuthnException ex = null;
  private String messageKey = null;
  private boolean inProgress = false;
  private boolean isAlternateAuthnSystem = false;
  
  private final Boolean isRecoverable = null;
  private Map authnIds = null;
  
  private String userName = null;
  




  public String getPcvId()
  {
    return this.pcvId;
  }
  
  public void setPcvId(String pcvId)
  {
    this.pcvId = pcvId;
  }
  
  public PasswordCredentialValidatorAuthnException getException()
  {
    return this.ex;
  }
  
  public void setException(PasswordCredentialValidatorAuthnException ex)
  {
    this.ex = ex;
  }
  
  public String getMessageKey()
  {
    if (this.messageKey == null)
    {
      return this.ex.getMessageKey();
    }
    

    return this.messageKey;
  }
  

  public void setMessageKey(String messageKey)
  {
    this.messageKey = messageKey;
  }
  
  public String getRadiusServerError()
  {
    String serverError = null;
    
    if ((isError()) && ((this.ex.getCause() instanceof RadiusAdminUserException)))
    {
      RadiusAdminUserException re = (RadiusAdminUserException)this.ex.getCause();
      serverError = re.getReplyMessage();
    }
    
    return serverError;
  }
  

  public Map getAuthnIds()
  {
    return this.authnIds;
  }
  

  public void setAuthnIds(Map authnIds)
  {
    this.authnIds = authnIds;
  }
  
  public String getUserName()
  {
    return this.userName;
  }
  
  public void setUserName(String userName)
  {
    this.userName = userName;
  }
  
  public boolean isRecoverable()
  {
    if (this.isRecoverable == null)
    {
      return this.ex.isRecoverable();
    }
    

    return this.isRecoverable.booleanValue();
  }
  

  public boolean isError()
  {
    return this.ex != null;
  }
  
  public boolean isSuccess()
  {
    return (this.ex == null) && (!isInProgress());
  }
  
  public boolean isInProgress()
  {
    return this.inProgress;
  }
  
  public void setInProgress(boolean inProgress)
  {
    this.inProgress = inProgress;
  }
  
  public boolean isAlternateAuthnSystem()
  {
    return this.isAlternateAuthnSystem;
  }
  
  public void setAlternateAuthnSystem(boolean alternateAuthnSystem)
  {
    this.isAlternateAuthnSystem = alternateAuthnSystem;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\idp\HtmlFormLoginContext.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */