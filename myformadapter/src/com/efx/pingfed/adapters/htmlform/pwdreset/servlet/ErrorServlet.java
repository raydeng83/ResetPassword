package com.efx.pingfed.adapters.htmlform.pwdreset.servlet;

import com.pingidentity.sdk.locale.LanguagePackMessages;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.websso.profiles.ProcessRuntimeException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.util.Map;


public class ErrorServlet
  extends AbstractPasswordResetServlet
{
  private static Log logger = LogFactory.getLog(ErrorServlet.class);
  
  public void doGet(HttpServletRequest request, HttpServletResponse response) {
    logger.debug("GET Request to /ext/pwdreset/Error");
    render(request, response, getDefaultParams(request));
  }
  
  public void doPost(HttpServletRequest request, HttpServletResponse response) {
    logger.debug("POST Request to /ext/pwdreset/Error");
    render(request, response, getDefaultParams(request));
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
        logger.error("Error encoding message: " + e.getMessage());
        if (logger.isDebugEnabled())
        {
          logger.debug("Error encoding message", e);
        }
        
        message = "forgot-password-error.unknownError";
      }
      params.put("errorMessageKey", message);
    }
    else {
      params.put("errorMessageKey", "forgot-password-error.unknownError");
    }
    
    params.put("url", request.getContextPath() + "/");
    

    try
    {
      String templateName = "forgot-password-error.html";
      String adapterId = getAdapterId(request, response);
      
      if (adapterId != null)
      {
        templateName = getPasswordManagementConfiguration(adapterId).getErrorTemplate();
      }
      
      TemplateRendererUtil.render(request, response, templateName, params);
    }
    catch (Exception ex)
    {
      logger.error("Error on Request to /ext/pwdreset/Error: " + ex.getMessage());
      if (logger.isDebugEnabled())
      {
        logger.debug("Error on Request to /ext/pwdreset/Error", ex);
      }
      
      throw new ProcessRuntimeException(ex);
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\servlet\ErrorServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */