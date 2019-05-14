package com.pingidentity.adapters.htmlform.pwdreset.servlet;

import com.pingidentity.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import com.pingidentity.adapters.htmlform.pwdreset.util.UrlUtil;
import com.pingidentity.sdk.locale.LanguagePackMessages;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.net.URLEncoder;
import java.util.Map;
import java.util.ResourceBundle;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.websso.profiles.ProcessRuntimeException;




public class SuccessServlet
  extends AbstractPasswordResetServlet
{
  private static Log logger = LogFactory.getLog(SuccessServlet.class);
  




  public void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    logger.debug("GET Request to /ext/pwdreset/Success");
    setStage("stage4Start", request, response);
    render(request, response, getDefaultParams(request));
  }
  
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    logger.debug("POST Request to /ext/pwdreset/Success");
    UrlUtil urlUtil = new UrlUtil(request);
    
    if (!validStage("stage4Start", request, response)) {
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
      return;
    }
    
    String target = (String)this.sessionUtil.get("prSuccessTarget", request, response);
    clearState(request, response);
    redirect(response, target);
  }
  
  private void render(HttpServletRequest request, HttpServletResponse response, Map<String, Object> params)
  {
    String message = request.getParameter("message");
    if ((message != null) && (!message.isEmpty()))
    {
      LanguagePackMessages lpm = (LanguagePackMessages)params.get("pluginTemplateMessages");
      if (!lpm.getResourceBundle().containsKey(message))
      {
        throw new ProcessRuntimeException("The message ID " + message + " does not exist.");
      }
      
      try
      {
        message = URLEncoder.encode(message, "UTF-8");
      } catch (Exception e) {
        logger.error("Error encoding message", e);
        message = "forgot-password-success.passwordChangeSuccessful";
      }
      params.put("messageKey", message);
    }
    else {
      params.put("messageKey", "forgot-password-success.passwordChangeSuccessful");
    }
    
    params.put("url", request.getContextPath() + "/");
    
    String target = (String)this.sessionUtil.get("prSuccessTarget", request, response);
    if ((target != null) && (!target.isEmpty())) {
      params.put("successContinue", "true");
    }
    
    try
    {
      PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
      TemplateRendererUtil.render(request, response, configuration.getSuccessTemplate(), params);
    }
    catch (Exception ex)
    {
      logger.error("Error on Request to /ext/pwdreset/Success", ex);
      throw new ProcessRuntimeException(ex);
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\servlet\SuccessServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */