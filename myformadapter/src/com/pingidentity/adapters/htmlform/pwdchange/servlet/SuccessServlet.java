package com.pingidentity.adapters.htmlform.pwdchange.servlet;

import com.pingidentity.adapters.htmlform.pwdchange.common.ChangePasswordSessionState;
import com.pingidentity.adapters.htmlform.pwdchange.common.PasswordChangeConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.servlet.AbstractPasswordResetServlet;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.sourceid.oauth20.protocol.Parameters;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;

public class SuccessServlet extends AbstractPasswordResetServlet
{
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException
  {
    doPost(req, resp);
  }
  
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
    throws IOException
  {
    ChangePasswordSessionState state = null;
    PasswordChangeConfiguration configuration = null;
    try
    {
      state = ChangePasswordSessionState.get(req, resp);
      configuration = getPasswordChangeConfiguration(state);
    }
    catch (IllegalArgumentException e)
    {
      resp.sendError(404);
      return;
    }
    
    String targetUrl = state.getTargetUrl();
    String username = req.getParameter("pf.username");
    if ((state.isFromHtmlFormAdapter()) && (StringUtils.isNotBlank(username)))
    {
      targetUrl = targetUrl + "?pf.username=" + URLEncoder.encode(username, "UTF-8");
    }
    
    if (((!state.isFromHtmlFormAdapter()) || (state.getAuthnPolicy().allowUserInteraction())) && (configuration.isAllowsChangePassword()))
    {
      Map<String, Object> params = new HashMap();
      
      params.put("headerMessage", StringUtils.isNotBlank(state.getTargetUrl()) ? "passwordChangedHeaderMessage" : "passwordChangedNoTargetResourceHeaderMessage");
      
      params.put("authnMessageKey", null);
      params.put("redirectUrl", targetUrl);
      params.put("linkText", "passwordChangedLinkText");
      params.put(Parameters.CLIENT_ID, state.getClientId());
      params.put("spAdapterId", state.getSpAdapterId());
      
      TemplateRendererUtil.render(req, resp, configuration.getChangePasswordMessageTemplateName(), params);
    }
    state.delete(req, resp);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\servlet\SuccessServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */