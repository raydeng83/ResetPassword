package com.pingidentity.adapters.htmlform.pwdchange.handler;

import com.pingidentity.adapters.htmlform.idp.AuthenticateFormHandler;
import com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter;
import com.pingidentity.adapters.htmlform.idp.HtmlFormLoginContext;
import com.pingidentity.adapters.htmlform.pwdchange.common.ChangePasswordSessionState;
import com.pingidentity.adapters.htmlform.pwdchange.common.PasswordChangeConfiguration;
import com.pingidentity.adapters.htmlform.pwdchange.model.IdentifyForm;
import com.pingidentity.adapters.htmlform.pwdchange.render.ChangePasswordWithForm;
import com.pingidentity.adapters.htmlform.pwdchange.type.IdentifyResult;
import com.pingidentity.adapters.htmlform.pwdreset.util.PwdResetAuditLogger;
import com.pingidentity.common.security.AccountLockingService;
import com.pingidentity.common.security.LockingService;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.sourceid.saml20.adapter.state.TransactionalStateSupport;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.service.AdapterAuthnSourceKey;
import org.sourceid.saml20.service.impl.proxy.LockingServiceFactory;

public class IdentifyHandler
  extends BaseHandler
{
  private PasswordChangeConfiguration configuration;
  
  public IdentifyHandler(PasswordChangeConfiguration configuration)
  {
    this.configuration = configuration;
  }
  


  public IdentifyResult authenticateExistingCredentials(IdentifyForm identifyForm, HttpServletRequest req, HttpServletResponse resp)
    throws IOException
  {
    ChangePasswordSessionState state = ChangePasswordSessionState.get(req, resp);
    
    LockingService accountLockingService = MgmtFactory.getAccountLockingService().getInstance(HtmlFormIdpAuthnAdapter.class.getSimpleName() + this.configuration.getAdapterId());
    
    PwdResetAuditLogger.init("PWD_CHANGE", req, resp);
    PwdResetAuditLogger.setUserName(identifyForm.getUsername());
    PwdResetAuditLogger.setAuthnSourceId(new AdapterAuthnSourceKey(this.configuration.getAdapterId()));
    IdentifyResult result;
    IdentifyResult result; if (accountLockingService.isLocked(req.getRemoteAddr() + identifyForm.getUsername(), this.configuration.getNumInvalidAttempts(), 
      AccountLockingService.getLockoutPeriod()))
    {
      PwdResetAuditLogger.logFailure("Account is locked.");
      PwdResetAuditLogger.cleanupAuthnAttempt();
      result = IdentifyResult.AccountLocked;
    }
    else
    {
      AuthenticateFormHandler authenticateFormHandler = new AuthenticateFormHandler(state.getSessionKeyLoginContext(), this.configuration, accountLockingService);
      

      Map<String, Object> inParameters = new HashMap();
      TransactionalStateSupport transactionalStateSupport = getTransactionalStateSupport(req, resp, state);
      
      HtmlFormLoginContext loginContext = authenticateFormHandler.authenticateForm(req, resp, inParameters, state.getAuthnPolicy(), state.getEntityId(), identifyForm.getUsername(), identifyForm.getCurrentPassword(), "", null, transactionalStateSupport, false, null, state
      
        .isChainedUsernameAvailable(), false, true);
      
      PwdResetAuditLogger.setPcvId(loginContext.getPcvId());
      


      if ((loginContext.isSuccess()) || ((loginContext.isError()) && (loginContext.isRecoverable())))
      {
        IdentifyResult result = IdentifyResult.Authenticated;
        state.setPcvId(loginContext.getPcvId());
        state.save(req, resp);
      }
      else
      {
        result = IdentifyResult.Error;
        ChangePasswordWithForm changePasswordWithForm = new ChangePasswordWithForm();
        changePasswordWithForm.render(req, resp, identifyForm.getErrorList(), 
          StringUtils.isNotBlank(loginContext.getMessageKey()) ? loginContext.getMessageKey() : "authn.srvr.msg.invalid.credentials");
        PwdResetAuditLogger.logFailure("Incorrect current password or account is locked.");
        PwdResetAuditLogger.cleanupAuthnAttempt();
        accountLockingService.logFailedLogin(req.getRemoteAddr() + identifyForm.getUsername());
      }
    }
    
    return result;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\handler\IdentifyHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */