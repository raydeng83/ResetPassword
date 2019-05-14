package com.efx.pingfed.adapters.htmlform.pwdreset.servlet;

import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter;
import com.pingidentity.adapters.htmlform.idrecovery.common.RecoverUsernameConfigHelper;
import com.pingidentity.adapters.htmlform.idrecovery.common.RecoverUsernameConfiguration;
import com.pingidentity.adapters.htmlform.pwdchange.common.ChangePasswordSessionState;
import com.pingidentity.adapters.htmlform.pwdchange.common.PasswordChangeConfigHelper;
import com.pingidentity.adapters.htmlform.pwdchange.common.PasswordChangeConfiguration;
import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordManagementConfiguration;
import com.efx.pingfed.adapters.htmlform.pwdreset.common.PasswordResetConfigHelper;
import com.efx.pingfed.adapters.htmlform.pwdreset.handler.AccountUnlockHandler;
import com.pingidentity.adapters.htmlform.pwdreset.model.BaseForm;
import com.pingidentity.adapters.htmlform.pwdreset.type.ResetResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import com.efx.pingfed.adapters.htmlform.pwdreset.util.UrlUtil;
import com.pingidentity.common.security.AccountLockingService;
import com.pingidentity.common.util.CrossSiteRequestForgeryHelper;
import com.pingidentity.common.util.EscapeUtils;
import com.pingidentity.locale.LocaleUtil;
import com.pingidentity.sdk.locale.LanguagePackMessages;
import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sourceid.saml20.domain.LocalSettings;
import org.sourceid.saml20.domain.mgmt.LocalSettingsManager;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.websso.profiles.ProcessRuntimeException;
import org.sourceid.websso.servlet.adapter.Handler;

public abstract class AbstractPasswordResetServlet
        extends HttpServlet
        implements Handler
{
  protected final Logger logger = LogManager.getLogger(getClass());
  public static final String STAGE_1_START = "stage1Start";
  public static final String STAGE_1_END = "stage1End";
  public static final String STAGE_2_START = "stage2Start";
  public static final String STAGE_2_END = "stage2End";
  public static final String STAGE_2_AUTHENTICATED = "stage2Authenticated";
  public static final String STAGE_3_START = "stage3Start";
  public static final String STAGE_3_END = "stage3End";
  public static final String STAGE_4_START = "stage4Start";
  public static final String INVALID_STATE_MESSAGE = "Invalid state (unauthorized method)";
  protected SessionStateUtil sessionUtil = new SessionStateUtil();

  public void handle(HttpServletRequest req, HttpServletResponse resp)
          throws ServletException, IOException
  {
    try
    {
      super.service(req, resp);
    }
    catch (ProcessRuntimeException e)
    {
      throw e;
    }
    catch (Exception e)
    {
      String method = req.getMethod();
      String pathInfo = req.getPathInfo();
      this.logger.error("An error has occurred in " + method + " " + pathInfo, e);
      PwdResetAuditLogger.logFailure("System error (see server log)");
      UrlUtil urlUtil = new UrlUtil(req);
      redirect(resp, urlUtil.buildErrorUrl("forgot-password-error.unknownError"));
    }
  }

  protected Map<String, Object> getDefaultParams(HttpServletRequest req)
  {
    Map<String, Object> params = new HashMap();

    Locale userLocale = LocaleUtil.getUserLocale(req);
    LanguagePackMessages lpm = new LanguagePackMessages("pingfederate-messages", userLocale);
    params.put("pluginLocale", req.getLocale());
    params.put("pluginTemplateMessages", lpm);
    params.put("returnInfo", "");

    return params;
  }

  protected String getTargetResource(HttpServletRequest request)
  {
    return request.getHeader("targetResource");
  }

  public void redirect(HttpServletResponse response, String servletPath)
  {
    redirect(response, servletPath, true);
  }

  public void redirect(HttpServletResponse response, String servletPath, boolean escape)
  {
    try
    {
      String path = escape ? EscapeUtils.escape(servletPath) : servletPath;
      response.sendRedirect(path);
    }
    catch (IOException e)
    {
      this.logger.error("Error redirecting to: " + servletPath, e);
    }
  }

  protected boolean fromHtmlFormAdapter(String targetResource)
  {
    String baseUrl = MgmtFactory.getLocalSettingsManager().getLocalSettings().getBaseUrl();
    return (StringUtils.isNotBlank(targetResource)) && (targetResource.startsWith(baseUrl));
  }

  protected PasswordManagementConfiguration getPasswordManagementConfiguration(String adapterId)
  {
    return PasswordResetConfigHelper.get(adapterId);
  }

  protected PasswordManagementConfiguration getPasswordManagementConfiguration(HttpServletRequest request, HttpServletResponse response)
  {
    String adapterId = getAdapterId(request, response);
    return PasswordResetConfigHelper.get(adapterId);
  }

  protected PasswordChangeConfiguration getPasswordChangeConfiguration(ChangePasswordSessionState state)
  {
    return PasswordChangeConfigHelper.get(state.getIdpAdapterId());
  }

  protected RecoverUsernameConfiguration getRecoverUsernameConfiguration(HttpServletRequest request, HttpServletResponse response)
  {
    String adapterId = getAdapterId(request, response);
    return RecoverUsernameConfigHelper.get(adapterId);
  }

  protected void clearState(HttpServletRequest request, HttpServletResponse response)
  {
    this.sessionUtil.remove("prCount", request, response);
    this.sessionUtil.remove("prCodeMap", request, response);
    this.sessionUtil.remove("prUsername", request, response);
    this.sessionUtil.remove("prReferrer", request, response);
    this.sessionUtil.remove("prStage", request, response);
    this.sessionUtil.remove("cSRFToken", request, response);
    this.sessionUtil.remove("prPPMRequestId", request, response);
    this.sessionUtil.remove("prSuccessTarget", request, response);
    this.sessionUtil.remove("pcvId", request, response);
    this.sessionUtil.remove("adapterId", request, response);
    this.sessionUtil.remove("prEnableRememberUsername", request, response);
  }

  protected void setStage(String stage, HttpServletRequest request, HttpServletResponse response)
  {
    this.sessionUtil.add("prStage", stage, request, response);
  }

  protected boolean validStage(String stage, HttpServletRequest request, HttpServletResponse response)
  {
    if (stage != null)
    {
      String lastStage = (String)this.sessionUtil.get("prStage", request, response);
      return stage.equals(lastStage);
    }
    return false;
  }

  protected String validateCSRFToken(HttpServletRequest request, HttpServletResponse response)
  {
    String cSRFToken = CrossSiteRequestForgeryHelper.getCSRFToken(request, response);
    String cSRFTokenForm = request.getParameter("cSRFToken");
    if (!StringUtils.isAlphanumeric(cSRFTokenForm))
    {
      this.logger.error("CSRF token is either not found in the request or not alphanumeric.");
      return null;
    }
    if (!cSRFTokenForm.equals(cSRFToken))
    {
      this.logger.error("CSRF tokens don't match: cSRFTokenForm=" + cSRFTokenForm + ", cSRFToken=" + cSRFToken + ".");
      return null;
    }
    return cSRFToken;
  }

  protected String getAdapterId(HttpServletRequest request, HttpServletResponse response)
  {
    String sessionAdapterId = (String)this.sessionUtil.get("adapterId", request, response);
    String requestAdapterId = request.getParameter("AdapterId");
    if (requestAdapterId == null) {
      requestAdapterId = request.getParameter("adapterId");
    }
    return sessionAdapterId != null ? sessionAdapterId : requestAdapterId;
  }

  protected String unlockAccount(HttpServletRequest request, HttpServletResponse response, UrlUtil urlUtil, String username, String targetResource, AccountUnlockHandler unlockHandler)
  {
    PwdResetAuditLogger.init("ACCOUNT_UNLOCK", request, response);
    ResetResult result = unlockHandler.unlockAccount(username, request, response);
    String url = null;
    if (result == ResetResult.Success)
    {
      PwdResetAuditLogger.log();
      this.sessionUtil.add("prSuccessTarget", targetResource, request, response);
      resetLoginAttempt(request, response, username);
      url = getUnlockSuccessful(request, response);
    }
    else
    {
      PwdResetAuditLogger.logFailure();
      url = urlUtil.buildErrorUrl("account-unlock.error");
    }
    return url;
  }

  private void resetLoginAttempt(HttpServletRequest request, HttpServletResponse response, String username)
  {
    AccountLockingService lockingService = AccountLockingService.forName(HtmlFormIdpAuthnAdapter.class.getSimpleName() + getAdapterId(request, response));
    lockingService.clearFailedLogins(request.getRemoteAddr() + username);
  }

  private String getUnlockSuccessful(HttpServletRequest request, HttpServletResponse response)
  {
    UrlUtil urlUtil = new UrlUtil(request);
    String url = null;
    try
    {
      url = urlUtil.buildUnlockSuccessUrl();
    }
    catch (Exception ex)
    {
      this.logger.error("Error while processing a account unlock. ", ex.getMessage());
      throw new ProcessRuntimeException(ex);
    }
    return url;
  }

  protected String getSuccessActionUrl(HttpServletRequest request, HttpServletResponse response, UrlUtil urlUtil, PasswordManagementConfiguration configuration, BaseForm form)
  {
    ResetResult accountStatus = ResetResult.None;
    AccountUnlockHandler unlockHandler = null;
    String url = null;
    if (configuration.isEnableAccountUnlock())
    {
      unlockHandler = new AccountUnlockHandler(configuration);
      accountStatus = unlockHandler.isUserAccountLocked(form.getUsername(), request, response);
    }
    if (ResetResult.Locked == accountStatus)
    {
      url = unlockAccount(request, response, urlUtil, form.getUsername(), form.getTargetResource(), unlockHandler);
    }
    else if (ResetResult.Error == accountStatus)
    {
      PwdResetAuditLogger.logFailure();
      url = urlUtil.buildErrorUrl("account-unlock.error");
    }
    else
    {
      PwdResetAuditLogger.log();
      url = urlUtil.buildResetUrl();
    }
    return url;
  }
}
