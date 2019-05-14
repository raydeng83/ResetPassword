package com.pingidentity.adapters.htmlform.pwdchange.render;

import com.pingidentity.adapters.htmlform.pwdchange.common.ChangePasswordSessionState;
import com.pingidentity.adapters.htmlform.pwdchange.common.PasswordChangeConfigHelper;
import com.pingidentity.adapters.htmlform.pwdchange.common.PasswordChangeConfiguration;
import com.pingidentity.common.util.HTMLEncoder;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.sourceid.oauth20.protocol.Parameters;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.domain.CaptchaSettings;
import org.sourceid.saml20.domain.mgmt.CaptchaManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;

public class ChangePasswordWithForm
{
  public void render(HttpServletRequest req, HttpServletResponse resp, List<String> errorMessageKeyList, String authnMessageKey) throws java.io.IOException
  {
    ChangePasswordSessionState state = ChangePasswordSessionState.get(req, resp);
    PasswordChangeConfiguration configuration = PasswordChangeConfigHelper.get(state.getIdpAdapterId());
    String username = StringUtils.defaultIfEmpty(state.getChainedUsername(), StringUtils.defaultString(req.getParameter("pf.username")));
    
    if ((!state.isFromHtmlFormAdapter()) || ((state.getAuthnPolicy().allowUserInteraction()) && (configuration.isAllowsChangePassword())))
    {
      boolean isPendingPwdChage = (StringUtils.isNotEmpty(req.getParameter("pf.passwordExpiring"))) && (Boolean.TRUE.toString().equals(req.getParameter("pf.passwordExpiring")));
      
      Map<String, Object> params = new HashMap();
      
      params.put("url", req.getContextPath() + "/ext/pwdchange/Identify");
      params.put("name", "pf.username");
      params.put("username", HTMLEncoder.encode(username));
      params.put("pass", "pf.pass");
      params.put("newPass1", "pf.new.pass1");
      params.put("newPass2", "pf.new.pass2");
      params.put("ok", "pf.ok");
      params.put("cancel", "pf.cancel");
      params.put("errorMessageKeys", errorMessageKeyList);
      params.put("authnMessageKey", authnMessageKey);
      params.put("passwordExpiring", "pf.passwordExpiring");
      params.put("isPasswordExpiring", Boolean.valueOf(isPendingPwdChage));
      
      params.put("hideChainedUsername", Boolean.valueOf((!state.isChainedUsernameAvailable()) || (!configuration.isAllowUsernameEdits()) || (!configuration.isEnableRememberMyUsername())));
      params.put("usernameNotChained", Boolean.valueOf(!state.isChainedUsernameAvailable()));
      params.put(Parameters.CLIENT_ID, state.getClientId());
      params.put("spAdapterId", state.getSpAdapterId());
      params.put("captchaEnabled", Boolean.valueOf(configuration.isCaptchaEnabledPasswordChange()));
      if (configuration.isCaptchaEnabledPasswordChange())
      {
        params.put("siteKey", MgmtFactory.getCaptchaManager().getCaptchaSettings().getSiteKey());
      }
      
      TemplateRendererUtil.render(req, resp, configuration.getChangePasswordTemplateName(), params);
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\render\ChangePasswordWithForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */