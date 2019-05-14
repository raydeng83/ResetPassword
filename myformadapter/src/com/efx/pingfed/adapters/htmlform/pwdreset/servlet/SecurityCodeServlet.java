package com.efx.pingfed.adapters.htmlform.pwdreset.servlet;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.efx.pingfed.adapters.htmlform.pwdreset.handler.SecurityCodeHandler;
import com.pingidentity.adapters.htmlform.pwdreset.model.SecurityCodeForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.SecurityCodeResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.efx.pingfed.adapters.htmlform.pwdreset.util.UrlUtil;
import com.pingidentity.common.util.CrossSiteRequestForgeryHelper;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.websso.profiles.ProcessRuntimeException;





public class SecurityCodeServlet
        extends AbstractPasswordResetServlet
{
  private static Log logger = LogFactory.getLog(SecurityCodeServlet.class);

  public void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    logger.debug("GET Request to /ext/pwdreset/SecurityCode");

    UrlUtil urlUtil = new UrlUtil(request);

    // if ((!validStage("stage1End", request, response)) || (!validResetType(request, response))) {
    //   PwdResetAuditLogger.logFailure("Invalid state (unauthorized method)");
    //   redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
    //   return;
    // }

    Map<String, Object> defaultParams = getDefaultParams(request);

    String cSRFToken = CrossSiteRequestForgeryHelper.getCSRFToken(request, response);
    defaultParams.put("cSRFToken", cSRFToken);

    PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);

    if (configuration.getResetType() != null) {
      if (configuration.getResetType().equals("SMS")) {
        defaultParams.put("sms", "true");
      } else {
        defaultParams.put("email", "true");
      }
    } else {
      defaultParams.put("email", "true");
    }

    render(request, response, defaultParams);
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response)
  {
    UrlUtil urlUtil = new UrlUtil(request);
    PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
    PwdResetAuditLogger.init("PWD_RESET_REQUEST_RESPONSE", request, response);
    logger.debug("POST Request to /ext/pwdreset/SecurityCode");

    Map<String, Object> defaultParams = getDefaultParams(request);

    String cSRFToken = validateCSRFToken(request, response);
    // if ((cSRFToken == null) || (!validStage("stage2Start", request, response)) || (!validResetType(request, response))) {
    //   PwdResetAuditLogger.logFailure("Invalid state (unauthorized method)");
    //   redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
    //   return;
    // }
    defaultParams.put("cSRFToken", cSRFToken);

    SecurityCodeForm form = new SecurityCodeForm(this.sessionUtil, request, response);
    PwdResetAuditLogger.setUserName(form.getUsername());
    SecurityCodeHandler handler = new SecurityCodeHandler(configuration);
    SecurityCodeResult validationResult = handler.validateCode(form, request, response);

    if (configuration.getResetType() != null) {
      if (configuration.getResetType().equals("SMS")) {
        defaultParams.put("sms", "true");
      } else {
        defaultParams.put("email", "true");
      }
    } else {
      defaultParams.put("email", "true");
    }

    setStage("stage2End", request, response);

    switch (validationResult) {
      case Error:
        PwdResetAuditLogger.logFailure();
        redirect(response, urlUtil.buildErrorUrl("forgot-password-error.codeMismatch"));
        break;
      case Success:
        setStage("stage2Authenticated", request, response);
        String url = getSuccessActionUrl(request, response, urlUtil, configuration, form);
        redirect(response, url);
        break;

      case CodeExpired:
        PwdResetAuditLogger.logFailure("OTP expired");
        redirect(response, urlUtil.buildErrorUrl("forgot-password-error.codeExpired"));
        break;
      case InvalidCode:
        PwdResetAuditLogger.logFailure("Invalid OTP");
        defaultParams.put("errorMessageKey", "forgot-password-error.codeMismatch");
        render(request, response, defaultParams);
        break;

      case Cancel:
        logger.debug("OTP request canceled");
        clearState(request, response);
        redirect(response, urlUtil.buildCancelUrl(form.getTargetResource()));
        break;
      case TooManyAttempts:
        PwdResetAuditLogger.logFailure("Exceeded OTP retry attempts");
        redirect(response, urlUtil.buildErrorUrl("forgot-password-error.codeValidationCountExceeded"));
        break;
      case NoCode:
        PwdResetAuditLogger.logFailure("No OTP provided");
        defaultParams.put("errorMessageKey", "forgot-password-resume.noSecurityCode");
        render(request, response, defaultParams);
    }

  }

  private void render(HttpServletRequest request, HttpServletResponse response, Map<String, Object> params)
  {
    params.put("url", request.getContextPath() + "/");
    params.put("name", "SecurityCode");
    params.put("ok", "Change");
    params.put("cancel", "Cancel");


    setStage("stage2Start", request, response);


    try
    {
      PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
      TemplateRendererUtil.render(request, response, configuration.getCodeTemplate(), params);
    }
    catch (Exception ex)
    {
      logger.error("Error on Request to /ext/pwdreset/SecurityCode", ex);
      throw new ProcessRuntimeException(ex);
    }
  }




  private boolean validResetType(HttpServletRequest request, HttpServletResponse response)
  {
    PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
    return ("OTP".equals(configuration.getResetType())) || ("SMS".equals(configuration.getResetType()));
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\servlet\SecurityCodeServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */