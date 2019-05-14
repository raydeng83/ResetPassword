package com.pingidentity.adapters.htmlform.pwdchange.common;

import java.io.Serializable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.state.SessionStateSupport;



public class ChangePasswordSessionState
  implements Serializable
{
  private static final String CHANGE_PASSWORD_STATE_NAME = "ChangePasswordSessionState";
  private static final long serialVersionUID = -5577425199137522753L;
  private String clientId = null;
  private String spAdapterId = null;
  private String idpAdapterId = null;
  private String targetUrl = null;
  private String pcvId = null;
  private String chainedUsername = null;
  private String entityId = null;
  private String errorMessageKey = null;
  private String authnMessageKey = null;
  private String serverError = null;
  private String resumeId = null;
  
  private String sessionKeyLoginContext = null;
  
  private AuthnPolicy authnPolicy = null;
  
  private boolean chainedUsernameAvailable = false;
  private boolean fromHtmlFormAdapter = false;
  private boolean passwordExpiring = false;
  

  private boolean loginFailed;
  


  public static ChangePasswordSessionState get(HttpServletRequest req, HttpServletResponse resp)
  {
    SessionStateSupport sessionStateSupport = new SessionStateSupport();
    ChangePasswordSessionState state = (ChangePasswordSessionState)sessionStateSupport.getAttribute("ChangePasswordSessionState", req, resp);
    return state != null ? state : new ChangePasswordSessionState();
  }
  
  public void delete(HttpServletRequest req, HttpServletResponse resp)
  {
    SessionStateSupport sessionStateSupport = new SessionStateSupport();
    sessionStateSupport.removeAttribute("ChangePasswordSessionState", req, resp);
  }
  
  public void save(HttpServletRequest req, HttpServletResponse resp)
  {
    SessionStateSupport sessionStateSupport = new SessionStateSupport();
    sessionStateSupport.setAttribute("ChangePasswordSessionState", this, req, resp, false);
  }
  
  public String getTargetUrl()
  {
    return this.targetUrl;
  }
  
  public void setTargetUrl(String targetUrl)
  {
    this.targetUrl = targetUrl;
  }
  
  public String getIdpAdapterId()
  {
    return this.idpAdapterId;
  }
  
  public void setIdpAdapterId(String idpAdapterId)
  {
    this.idpAdapterId = idpAdapterId;
  }
  
  public String getPcvId()
  {
    return this.pcvId;
  }
  
  public void setPcvId(String pcvId)
  {
    this.pcvId = pcvId;
  }
  
  public String getClientId()
  {
    return this.clientId;
  }
  
  public void setClientId(String clientId)
  {
    this.clientId = clientId;
  }
  
  public String getSpAdapterId()
  {
    return this.spAdapterId;
  }
  
  public void setSpAdapterId(String spAdapterId)
  {
    this.spAdapterId = spAdapterId;
  }
  
  public boolean isChainedUsernameAvailable()
  {
    return this.chainedUsernameAvailable;
  }
  
  public void setChainedUsernameAvailable(boolean chainedUsernameAvailable)
  {
    this.chainedUsernameAvailable = chainedUsernameAvailable;
  }
  
  public String getSessionKeyLoginContext()
  {
    return this.sessionKeyLoginContext;
  }
  
  public void setSessionKeyLoginContext(String sessionKeyLoginContext)
  {
    this.sessionKeyLoginContext = sessionKeyLoginContext;
  }
  
  public String getChainedUsername()
  {
    return this.chainedUsername;
  }
  
  public void setChainedUsername(String chainedUsername)
  {
    this.chainedUsername = chainedUsername;
  }
  
  public AuthnPolicy getAuthnPolicy()
  {
    return this.authnPolicy;
  }
  
  public void setAuthnPolicy(AuthnPolicy authnPolicy)
  {
    this.authnPolicy = authnPolicy;
  }
  
  public boolean isFromHtmlFormAdapter()
  {
    return this.fromHtmlFormAdapter;
  }
  
  public void setFromHtmlFormAdapter(boolean fromHtmlFormAdapter)
  {
    this.fromHtmlFormAdapter = fromHtmlFormAdapter;
  }
  
  public boolean isLoginFailed()
  {
    return this.loginFailed;
  }
  
  public void setLoginFailed(boolean loginFailed)
  {
    this.loginFailed = loginFailed;
  }
  
  public String getEntityId()
  {
    return this.entityId;
  }
  
  public void setEntityId(String entityId)
  {
    this.entityId = entityId;
  }
  
  public String getErrorMessageKey()
  {
    return this.errorMessageKey;
  }
  
  public void setErrorMessageKey(String errorMessageKey)
  {
    this.errorMessageKey = errorMessageKey;
  }
  
  public String getAuthnMessageKey()
  {
    return this.authnMessageKey;
  }
  
  public void setAuthnMessageKey(String authnMessageKey)
  {
    this.authnMessageKey = authnMessageKey;
  }
  
  public String getServerError()
  {
    return this.serverError;
  }
  
  public void setServerError(String serverError)
  {
    this.serverError = serverError;
  }
  
  public boolean isPasswordExpiring()
  {
    return this.passwordExpiring;
  }
  
  public void setPasswordExpiring(boolean passwordExpiring)
  {
    this.passwordExpiring = passwordExpiring;
  }
  
  public String getResumeId()
  {
    return this.resumeId;
  }
  
  public void setResumeId(String resumeId)
  {
    this.resumeId = resumeId;
  }
  
  public static class Builder
  {
    private String clientId = null;
    private String spAdapterId = null;
    private String targetUrl = null;
    private String idpAdapterId = null;
    private String pcvId = null;
    private String sessionKeyLoginContext = null;
    private String chainedUsername = null;
    private String entityId = null;
    private String errorMessageKey = null;
    private String authnMessageKey = null;
    private String serverError = null;
    private String resumeId = null;
    
    private AuthnPolicy authnPolicy = null;
    
    private boolean chainedUsernameAvailable = false;
    private boolean fromHtmlFormAdapter = false;
    private boolean loginFailed = false;
    private boolean passwordExpiring = false;
    




    public Builder clientId(String clientId)
    {
      this.clientId = clientId;
      return this;
    }
    
    public Builder spAdapterId(String spAdapterId)
    {
      this.spAdapterId = spAdapterId;
      return this;
    }
    
    public Builder idpAdapterId(String idpAdapterId)
    {
      this.idpAdapterId = idpAdapterId;
      return this;
    }
    
    public Builder pcvId(String pcvId)
    {
      this.pcvId = pcvId;
      return this;
    }
    
    public Builder chainedUsername(String chainedUsername)
    {
      this.chainedUsername = chainedUsername;
      return this;
    }
    
    public Builder sessionKeyLoginContext(String sessionKeyLoginContext)
    {
      this.sessionKeyLoginContext = sessionKeyLoginContext;
      return this;
    }
    
    public Builder chainedUsernameAvailable(boolean chainedUsernameAvailable)
    {
      this.chainedUsernameAvailable = chainedUsernameAvailable;
      return this;
    }
    
    public Builder fromHtmlFormAdapter(boolean fromHtmlFormAdapter)
    {
      this.fromHtmlFormAdapter = fromHtmlFormAdapter;
      return this;
    }
    
    public Builder authnPolicy(AuthnPolicy authnPolicy)
    {
      this.authnPolicy = authnPolicy;
      return this;
    }
    
    public Builder targetUrl(String targetUrl)
    {
      this.targetUrl = targetUrl;
      return this;
    }
    
    public Builder serverError(String serverError)
    {
      this.serverError = serverError;
      return this;
    }
    
    public Builder resumeId(String resumeId)
    {
      this.resumeId = resumeId;
      return this;
    }
    
    public Builder authnMessageKey(String authnMessageKey)
    {
      this.authnMessageKey = authnMessageKey;
      return this;
    }
    
    public Builder errorMessageKey(String errorMessageKey)
    {
      this.errorMessageKey = errorMessageKey;
      return this;
    }
    
    public Builder entityId(String entityId)
    {
      this.entityId = entityId;
      return this;
    }
    
    public Builder loginFailed(boolean loginFailed)
    {
      this.loginFailed = loginFailed;
      return this;
    }
    
    public Builder passwordExpiring(boolean passwordExpiring)
    {
      this.passwordExpiring = passwordExpiring;
      return this;
    }
    
    public ChangePasswordSessionState build()
    {
      ChangePasswordSessionState state = new ChangePasswordSessionState();
      state.clientId = this.clientId;
      state.spAdapterId = this.spAdapterId;
      state.targetUrl = this.targetUrl;
      state.idpAdapterId = this.idpAdapterId;
      state.pcvId = this.pcvId;
      state.chainedUsernameAvailable = this.chainedUsernameAvailable;
      state.chainedUsername = this.chainedUsername;
      state.sessionKeyLoginContext = this.sessionKeyLoginContext;
      state.authnPolicy = this.authnPolicy;
      state.fromHtmlFormAdapter = this.fromHtmlFormAdapter;
      state.loginFailed = this.loginFailed;
      state.entityId = this.entityId;
      state.errorMessageKey = this.errorMessageKey;
      state.authnMessageKey = this.authnMessageKey;
      state.serverError = this.serverError;
      state.passwordExpiring = this.passwordExpiring;
      state.resumeId = this.resumeId;
      return state;
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\common\ChangePasswordSessionState.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */