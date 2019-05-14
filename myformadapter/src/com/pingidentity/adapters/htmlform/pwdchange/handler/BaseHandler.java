package com.pingidentity.adapters.htmlform.pwdchange.handler;

import com.pingidentity.adapters.htmlform.pwdchange.common.ChangePasswordSessionState;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.RandomStringUtils;
import org.sourceid.saml20.adapter.state.TransactionalStateSupport;
import org.sourceid.saml20.profiles.AdapterPathSupport;


public abstract class BaseHandler
{
  protected TransactionalStateSupport getTransactionalStateSupport(HttpServletRequest req, HttpServletResponse resp, ChangePasswordSessionState state)
  {
    String resumeId = state.getResumeId();
    if ((resumeId == null) || (resumeId.isEmpty())) {
      resumeId = RandomStringUtils.randomAlphanumeric(6);
      resumeId = AdapterPathSupport.convertPath(req, resp, resumeId);
      state.setResumeId(resumeId);
      state.save(req, resp);
    }
    return new TransactionalStateSupport(resumeId);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\handler\BaseHandler.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */