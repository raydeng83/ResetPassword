package com.pingidentity.adapters.htmlform.pwdreset.servlet;

import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.pingidentity.adapters.htmlform.pwdreset.handler.AccountUnlockHandler;
import com.pingidentity.adapters.htmlform.pwdreset.handler.AccountUnlockHandler.AccountUnlockSuccessAction;
import com.pingidentity.adapters.htmlform.pwdreset.model.AccountUnlockSuccessForm;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import com.pingidentity.adapters.htmlform.pwdreset.util.UrlUtil;
import com.pingidentity.sdk.template.TemplateRendererUtil;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.websso.profiles.ProcessRuntimeException;





public class AccountUnlockServlet
  extends AbstractPasswordResetServlet
{
  private static Log logger = LogFactory.getLog(AccountUnlockServlet.class);
  
  public void doGet(HttpServletRequest request, HttpServletResponse response)
  {
    logger.debug("GET Request to /ext/pwdreset/Unlock");
    
    UrlUtil urlUtil = new UrlUtil(request);
    
    if (!validStage("stage2Authenticated", request, response))
    {
      redirect(response, urlUtil.buildErrorUrl("forgot-password-error.invalidState"));
      return;
    }
    
    Map<String, Object> defaultParams = getDefaultParams(request);
    
    PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
    
    boolean isVerificationSecurityCode = !"OTL".equals(configuration.getResetType());
    
    defaultParams.put("showAction", Boolean.valueOf(isVerificationSecurityCode));
    
    if (isVerificationSecurityCode)
    {
      defaultParams.put("successMessage", "account-unlock.info");
    }
    else
    {
      defaultParams.put("successMessage", "account-unlock.unlockedMessage");
    }
    
    render(request, response, defaultParams);
  }
  

  private void render(HttpServletRequest request, HttpServletResponse response, Map<String, Object> params)
  {
    params.put("url", request.getContextPath() + "/");
    params.put("ok", "Unlock");
    params.put("reset", "Reset");
    params.put("cancel", "Cancel");
    
    try
    {
      PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
      TemplateRendererUtil.render(request, response, configuration.getUnlockTemplate(), params);
    }
    catch (Exception ex)
    {
      logger.error("Error on Request to /ext/pwdreset/Unlock", ex);
      throw new ProcessRuntimeException(ex);
    }
  }
  

  public void doPost(HttpServletRequest request, HttpServletResponse response)
  {
    UrlUtil urlUtil = new UrlUtil(request);
    
    PasswordManagementConfiguration configuration = getPasswordManagementConfiguration(request, response);
    
    AccountUnlockHandler successHandler = new AccountUnlockHandler(configuration);
    AccountUnlockSuccessForm form = new AccountUnlockSuccessForm(this.sessionUtil, request, response);
    AccountUnlockHandler.AccountUnlockSuccessAction formAction = successHandler.action(form, request, response);
    
    if (formAction.equals(AccountUnlockHandler.AccountUnlockSuccessAction.Continue))
    {
      String target = (String)this.sessionUtil.get("prSuccessTarget", request, response);
      clearState(request, response);
      
      redirect(response, target);
    }
    else if (formAction.equals(AccountUnlockHandler.AccountUnlockSuccessAction.Reset))
    {
      redirect(response, urlUtil.buildResetUrl());
    }
    else if (formAction.equals(AccountUnlockHandler.AccountUnlockSuccessAction.Cancel))
    {
      redirect(response, urlUtil.buildCancelUrl(form.getTargetResource()));
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\servlet\AccountUnlockServlet.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */