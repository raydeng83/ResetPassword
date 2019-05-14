package com.pingidentity.adapters.htmlform.pwdchange.handler;

import com.pingidentity.access.PasswordCredentialValidatorAccessor;
import com.pingidentity.adapters.htmlform.idp.AuthenticateFormHandler;
import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter;
import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapterUtils;
import com.pingidentity.adapters.htmlform.idp.HtmlFormLoginContext;
import com.pingidentity.adapters.htmlform.pwdchange.common.ChangePasswordSessionState;
import com.pingidentity.adapters.htmlform.pwdchange.common.PasswordChangeConfiguration;
import com.pingidentity.adapters.htmlform.pwdchange.model.IdentifyForm;
import com.pingidentity.adapters.htmlform.pwdchange.render.ChangePasswordWithForm;
import com.pingidentity.adapters.htmlform.pwdchange.type.ChangePasswordResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.pingidentity.adapters.htmlform.session.HtmlFormSessionStateSupport;
import com.pingidentity.common.event.Event;
import com.pingidentity.common.event.EventService;
import com.pingidentity.common.event.EventType;
import com.pingidentity.common.security.LockingService;
import com.pingidentity.locale.LocaleUtil;
import com.pingidentity.sdk.password.ChangeablePasswordCredential;
import com.pingidentity.sdk.password.PasswordCredentialValidatorAuthnException;
import com.pingidentity.sdk.password.ResettablePasswordCredential;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.sourceid.common.Util;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.state.TransactionalStateSupport;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.service.impl.proxy.LockingServiceFactory;



public class ChangePasswordHandler
  extends BaseHandler
{
  private static final Logger log = LogManager.getLogger(ChangePasswordHandler.class);
  
  private static final String ERROR_PASSWORD_CHANGE_FAILED = "defaultPasswordChangeError";
  
  private PasswordChangeConfiguration configuration;
  
  public ChangePasswordHandler(PasswordChangeConfiguration configuration)
  {
    this.configuration = configuration;
  }
  
  public ChangePasswordResult changePassword(IdentifyForm form, HttpServletRequest req, HttpServletResponse resp) throws IOException
  {
    ChangePasswordResult result = ChangePasswordResult.Error;
    ChangePasswordSessionState state = ChangePasswordSessionState.get(req, resp);
    HtmlFormLoginContext loginContext = new HtmlFormLoginContext();
    

    Map<String, Object> inParameters = new HashMap();
    
    TransactionalStateSupport transactionalStateSupport = getTransactionalStateSupport(req, resp, state);
    
    if (HtmlFormIdpAuthnAdapterUtils.supportsPasswordChange(state.getPcvId(), this.configuration.getPwmLocation()))
    {
      LockingService accountLockingService = MgmtFactory.getAccountLockingService().getInstance(HtmlFormIdpAuthnAdapter.class.getSimpleName() + this.configuration.getAdapterId());
      AuthenticateFormHandler authenticateFormHandler = new AuthenticateFormHandler(state.getSessionKeyLoginContext(), this.configuration, accountLockingService);
      

      try
      {
        ChangeablePasswordCredential pcv = (ChangeablePasswordCredential)new PasswordCredentialValidatorAccessor().getPasswordCredentialValidator(state.getPcvId());
        pcv.changePassword(form.getUsername(), form.getCurrentPassword(), form.getNewPassword(), null);
        
        PwdResetAuditLogger.log();
        

        if (this.configuration.getPwChangeReauthDelay() > 0)
        {
          try
          {
            log.debug("Delaying for " + this.configuration.getPwChangeReauthDelay() + " milliseconds before reauthentication can occur.");
            Thread.sleep(this.configuration.getPwChangeReauthDelay());
          }
          catch (Exception e)
          {
            log.warn("Failed to sleep for the configured Post-Password Change Re-Authentication Delay", e);
          }
        }
        

        loginContext = authenticateFormHandler.authenticateForm(req, resp, inParameters, state.getAuthnPolicy(), state.getEntityId(), form.getUsername(), form
          .getNewPassword(), "", loginContext.getPcvId(), transactionalStateSupport, true, null, state
          
          .isChainedUsernameAvailable(), false, true);
        
        if (loginContext.isSuccess())
        {
          result = ChangePasswordResult.Success;
          
          if ((pcv.isChangePasswordEmailNotifiable()) && (this.configuration.isEnableChangePasswordEmailNotification()))
          {
            Map authnIds = loginContext.getAuthnIds();
            if (authnIds != null)
            {
              Map<String, Object> eventParams = new HashMap();
              eventParams.put("givenName", authnIds.get("givenName"));
              String mailAttribute;
              String mailAttribute;
              if ((pcv instanceof ResettablePasswordCredential))
              {
                mailAttribute = ((ResettablePasswordCredential)pcv).getMailAttribute();
              }
              else
              {
                mailAttribute = "mail";
              }
              
              eventParams.put("mail", authnIds.get(mailAttribute));
              eventParams.put("template_name", new AttributeValue(this.configuration.getChangePasswordEmailNotificationTemplateName()));
              eventParams.put("username", new AttributeValue(form.getUsername()));
              eventParams.put("locale", LocaleUtil.getUserLocale(req));
              eventParams.put("adapterId", this.configuration.getAdapterId());
              eventParams.put("pcvId", state.getPcvId());
              
              EventService eventService = EventService.getService();
              eventService.addEvent(new Event(EventType.PASSWORD_CHANGE, eventParams));
            }
          }
          if ((!this.configuration.getSessionState().equals("None")) && (!Util.isEmpty(loginContext.getAuthnIds())))
          {
            HtmlFormSessionStateSupport sessionStateSupport = new HtmlFormSessionStateSupport();
            sessionStateSupport.setAttribute(this.configuration.SESSION_KEY_AUTHN, loginContext.getAuthnIds(), req, resp, true);
            sessionStateSupport.refreshSession(this.configuration.SESSION_KEY_LAST_ACTIVITY, req, resp);
          }
        }
        else if (loginContext.isRecoverable())
        {
          authenticateFormHandler.saveLoginState(req, resp, form.getUsername(), transactionalStateSupport, loginContext);
          ChangePasswordWithForm changePasswordWithForm = new ChangePasswordWithForm();
          changePasswordWithForm.render(req, resp, null, loginContext.getMessageKey());

        }
        else
        {

          transactionalStateSupport.removeAttribute(state.getSessionKeyLoginContext(), req, resp);
          redirectToHtmlFormAdapterForChallengeWithForm(req, resp, true, null, loginContext.getMessageKey(), null);
        }
      }
      catch (PasswordCredentialValidatorAuthnException e)
      {
        PwdResetAuditLogger.logFailure(e.getMessageKey());
        PwdResetAuditLogger.cleanupAuthnAttempt();
        if (e.isRecoverable())
        {
          authenticateFormHandler.saveLoginState(req, resp, form.getUsername(), transactionalStateSupport, loginContext);
          ChangePasswordWithForm changePasswordWithForm = new ChangePasswordWithForm();
          changePasswordWithForm.render(req, resp, null, e.getMessageKey());

        }
        else
        {

          transactionalStateSupport.removeAttribute(state.getSessionKeyLoginContext(), req, resp);
          redirectToHtmlFormAdapterForChallengeWithForm(req, resp, true, null, e.getMessageKey(), null);
        }
        loginContext.setAuthnIds(null);

      }
      catch (Exception e)
      {
        log.error("Error updating password", e);
        loginContext.setAuthnIds(null);
      }
      

    }
    else
    {
      redirectToHtmlFormAdapterForChallengeWithForm(req, resp, true, "defaultPasswordChangeError", null, null);
      log.debug("Password change attempt couldn't complete.  Password Credential Validator " + state
        .getPcvId() + " doesn't support password changes.  If you're using the standard LDAP PCV with ActiveDirectory, SSL must be enabled.  If you implemented a custom PCV, it must implement the ChangeablePasswordCredential interface.");
    }
    
    return result;
  }
  
  private void redirectToHtmlFormAdapterForChallengeWithForm(HttpServletRequest req, HttpServletResponse resp, boolean loginFailed, String errorMessageKey, String authnMessageKey, String serverError) throws IOException
  {
    ChangePasswordSessionState state = ChangePasswordSessionState.get(req, resp);
    if (state.isFromHtmlFormAdapter())
    {
      state.setLoginFailed(loginFailed);
      state.setErrorMessageKey(errorMessageKey);
      state.setAuthnMessageKey(authnMessageKey);
      state.setServerError(serverError);
      state.save(req, resp);
    }
    resp.sendRedirect(state.getTargetUrl());
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\handler\ChangePasswordHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */