package com.efx.pingfed.adapters.htmlform.pwdreset.util;

import org.sourceid.saml20.adapter.state.SessionStateSupport;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SessionStateUtil
{
  SessionStateSupport session;
  
  public SessionStateUtil()
  {
    this.session = new SessionStateSupport();
  }
  
  public void remove(String key, HttpServletRequest request, HttpServletResponse response) {
    this.session.removeAttribute(key, request, response);
  }
  
  public void add(String key, Object value, HttpServletRequest request, HttpServletResponse response)
  {
    this.session.setAttribute(key, value, request, response, true);
  }
  
  public Object get(String key, HttpServletRequest request, HttpServletResponse response) {
    return this.session.getAttribute(key, request, response);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdrese\\util\SessionStateUtil.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */