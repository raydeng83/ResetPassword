package com.efx.pingfed.adapters.htmlform.render;

import com.efx.pingfed.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter;
import com.pingidentity.common.util.CookieMonster;
import com.pingidentity.common.util.HTMLEncoder;
import com.pingidentity.localidentity.LocalIdentityProfile;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import org.apache.commons.lang.StringUtils;
import org.sourceid.common.Util;
import org.sourceid.oauth20.protocol.Parameters;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.domain.SpConnection;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.metadata.MetaDataFactory;
import org.sourceid.saml20.metadata.partner.MetadataDirectory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class ChallengeWithForm
{
  private String clientId = null;
  private String spAdapterId = null;
  private String url = null;
  private String idpAdapterId = null;
  private String localIdentityProfileId = null;
  private String name = null;
  private String entityId = null;
  private String errorMessageKey = null;
  private String authnMessageKey = null;
  private String serverError = null;
  private String pwmLocation = null;
  private String loginTemplateName = null;
  private String cookieName = null;
  private String resetType = null;
  
  private AuthnPolicy authnPolicy = null;
  
  private List<String> pwdCrdVal = new ArrayList();
  
  private boolean allowsChangePassword = false;
  private boolean enableRememberMyUsername = false;
  private boolean allowUsernameEdits = false;
  private boolean loginFailed = false;
  private boolean isChainedUsernameAvailable = false;
  private boolean enableUsernameRecovery = false;
  
  public void render(HttpServletRequest req, HttpServletResponse resp)
    throws IOException
  {
    if (this.authnPolicy.allowUserInteraction())
    {
      Map<String, Object> params = new HashMap();
      
      MetadataDirectory metadataDirectory = MetaDataFactory.getMetadataDirectory();
      SpConnection spConn = metadataDirectory.getSpConnection(this.entityId, false);
      String connectionName = spConn != null ? spConn.getName() : this.entityId;
      boolean usernameEditable = HtmlFormIdpAuthnAdapter.enableRememberChainedUsername(this.isChainedUsernameAvailable, this.allowUsernameEdits);
      boolean rememberChainedUsername = HtmlFormIdpAuthnAdapter.enableRememberChainedUsername(this.isChainedUsernameAvailable, this.allowUsernameEdits);
      String baseUrl = MgmtFactory.getLocalSettingsManager().getLocalSettings().getBaseUrl();
      
      params.put("url", this.url);
      params.put("adapterIdField", "pf.adapterId");
      params.put("adapterId", this.idpAdapterId);
      params.put("name", "pf.username");
      params.put("username", HTMLEncoder.encode(this.name) == null ? "" : HTMLEncoder.encode(this.name));
      params.put("usernameEditable", Boolean.valueOf(usernameEditable));
      params.put("isChainedUsernameAvailable", Boolean.valueOf(this.isChainedUsernameAvailable));
      params.put("pass", "pf.pass");
      params.put("ok", "pf.ok");
      params.put("cancel", "pf.cancel");
      params.put("passwordReset", "pf.passwordreset");
      params.put("usernameRecovery", "pf.usernamerecovery");
      params.put("loginFailed", Boolean.valueOf(this.loginFailed));
      params.put("connectionName", connectionName);
      params.put("entityId", this.entityId);
      params.put("baseUrl", baseUrl);
      params.put("supportsPasswordChange", Boolean.valueOf((this.allowsChangePassword) && (HtmlFormIdpAuthnAdapter.supportsPasswordChange(this.pwdCrdVal, this.pwmLocation))));
      params.put("supportsPasswordReset", Boolean.valueOf((this.allowsChangePassword) && (HtmlFormIdpAuthnAdapter.supportsPasswordReset(this.pwdCrdVal)) && (!HtmlFormIdpAuthnAdapter.isResetTypeNone(this.resetType))));
      params.put("supportsUsernameRecovery", Boolean.valueOf(HtmlFormIdpAuthnAdapter.supportsUsernameRecovery(this.enableUsernameRecovery, this.pwdCrdVal)));
      
      params.put("enableRememberUsername", Boolean.valueOf((rememberChainedUsername) && (this.enableRememberMyUsername)));
      params.put("rememberUsername", "pf.rememberUsername");
      
      String cookieValue = CookieMonster.getCookieValue(this.cookieName, req);
      params.put("rememberUsernameCookieExists", Boolean.valueOf(StringUtils.isNotBlank(cookieValue)));
      
      params.put("changePassword", "ChangePassword");
      
      Map<String, String> changePasswordParam = getChangePasswordParam();
      params.put("changePasswordUrl", Util.appendQueryParams(this.url, changePasswordParam));
      params.put("forgotPasswordUrl", HtmlFormIdpAuthnAdapter.getForgetPasswordUrl(baseUrl, this.idpAdapterId, this.url));
      params.put("recoverUsernameUrl", HtmlFormIdpAuthnAdapter.getRecoverUsernameUrl(baseUrl, this.idpAdapterId, this.url));
      params.put("errorMessageKey", this.errorMessageKey);
      params.put("authnMessageKey", this.authnMessageKey);
      params.put("serverError", this.serverError);
      params.put("spAdapterId", this.spAdapterId);
      params.put(Parameters.CLIENT_ID, this.clientId);
      if (this.localIdentityProfileId != null)
      {
        LocalIdentityProfile lip = MgmtFactory.getLocalIdentityProfileManager().getProfile(this.localIdentityProfileId);
        if (lip != null)
        {
          params.put("altAuthSources", lip.getAuthSourceStrings());
          params.put("registrationEnabled", Boolean.valueOf(lip.isRegistrationEnabled()));
          params.put("registrationValue", "pf.registration");
          params.put("alternateAuthnSystem", "pf.alternateAuthnSystem");
        }
      }
      TemplateRendererUtil.render(req, resp, this.loginTemplateName, params);
    }
  }
  
  private Map<String, String> getChangePasswordParam()
  {
    Map<String, String> changePasswordParam = new HashMap();
    changePasswordParam.put("ChangePassword", "true");
    
    return changePasswordParam;
  }
  
  public static class Builder
  {
    private String clientId = null;
    private String spAdapterId = null;
    private String url = null;
    private String idpAdapterId = null;
    private String localIdentityProfileId = null;
    private String name = null;
    private String entityId = null;
    private String errorMessageKey = null;
    private String authnMessageKey = null;
    private String serverError = null;
    private String pwmLocation = null;
    private String loginTemplateName = null;
    private String cookieName = null;
    private String resetType = null;
    
    private AuthnPolicy authnPolicy = null;
    
    private List<String> pwdCrdVal = new ArrayList();
    
    private boolean allowsChangePassword = false;
    private boolean enableRememberMyUsername = false;
    private boolean allowUsernameEdits = false;
    private boolean loginFailed = false;
    private boolean isChainedUsernameAvailable = false;
    private boolean enableUsernameRecovery = false;
    




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
    
    public Builder name(String name)
    {
      this.name = name;
      return this;
    }
    
    public Builder authnPolicy(AuthnPolicy authnPolicy)
    {
      this.authnPolicy = authnPolicy;
      return this;
    }
    
    public Builder url(String url)
    {
      this.url = url;
      return this;
    }
    
    public Builder serverError(String serverError)
    {
      this.serverError = serverError;
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
    
    public Builder localIdentityProfileId(String localIdentityProfileId)
    {
      this.localIdentityProfileId = localIdentityProfileId;
      return this;
    }
    
    public Builder pwmLocation(String pwmLocation)
    {
      this.pwmLocation = pwmLocation;
      return this;
    }
    
    public Builder loginTemplateName(String loginTemplateName)
    {
      this.loginTemplateName = loginTemplateName;
      return this;
    }
    
    public Builder cookieName(String cookieName)
    {
      this.cookieName = cookieName;
      return this;
    }
    
    public Builder resetType(String resetType)
    {
      this.resetType = resetType;
      return this;
    }
    
    public Builder pwdCrdVal(List<String> pwdCrdVal)
    {
      this.pwdCrdVal = pwdCrdVal;
      return this;
    }
    
    public Builder allowsChangePassword(boolean allowsChangePassword)
    {
      this.allowsChangePassword = allowsChangePassword;
      return this;
    }
    
    public Builder enableRememberMyUsername(boolean enableRememberMyUsername)
    {
      this.enableRememberMyUsername = enableRememberMyUsername;
      return this;
    }
    
    public Builder allowUsernameEdits(boolean allowUsernameEdits)
    {
      this.allowUsernameEdits = allowUsernameEdits;
      return this;
    }
    
    public Builder isChainedUsernameAvailable(boolean isChainedUsernameAvailable)
    {
      this.isChainedUsernameAvailable = isChainedUsernameAvailable;
      return this;
    }
    
    public Builder enableUsernameRecovery(boolean enableUsernameRecovery)
    {
      this.enableUsernameRecovery = enableUsernameRecovery;
      return this;
    }
    
    public ChallengeWithForm build()
    {
      ChallengeWithForm form = new ChallengeWithForm(null);
      form.clientId = this.clientId;
      form.spAdapterId = this.spAdapterId;
      form.idpAdapterId = this.idpAdapterId;
      form.name = this.name;
      form.authnPolicy = this.authnPolicy;
      form.url = this.url;
      form.serverError = this.serverError;
      form.authnMessageKey = this.authnMessageKey;
      form.errorMessageKey = this.errorMessageKey;
      form.entityId = this.entityId;
      form.loginFailed = this.loginFailed;
      
      form.localIdentityProfileId = this.localIdentityProfileId;
      form.pwmLocation = this.pwmLocation;
      form.loginTemplateName = this.loginTemplateName;
      form.cookieName = this.cookieName;
      form.pwdCrdVal = this.pwdCrdVal;
      form.allowsChangePassword = this.allowsChangePassword;
      form.enableRememberMyUsername = this.enableRememberMyUsername;
      form.allowUsernameEdits = this.allowUsernameEdits;
      form.isChainedUsernameAvailable = this.isChainedUsernameAvailable;
      form.enableUsernameRecovery = this.enableUsernameRecovery;
      form.resetType = this.resetType;
      return form;
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\render\ChallengeWithForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */