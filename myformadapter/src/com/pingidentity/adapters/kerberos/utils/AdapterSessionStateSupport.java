package com.pingidentity.adapters.kerberos.utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.sourceid.saml20.adapter.state.SessionStateSupport;



public class AdapterSessionStateSupport
  implements AdapterSession
{
  private SessionStateSupport sessionStateSupport;
  
  public AdapterSessionStateSupport()
  {
    this.sessionStateSupport = new SessionStateSupport();
  }
  
  public Object getAttribute(String name, HttpServletRequest req, HttpServletResponse resp) {
    return this.sessionStateSupport.getAttribute(name, req, resp);
  }
  
  public Object removeAttribute(String name, HttpServletRequest req, HttpServletResponse resp) {
    return this.sessionStateSupport.removeAttribute(name, req, resp);
  }
  
  public void setAttribute(String name, Object value, HttpServletRequest req, HttpServletResponse resp) {
    this.sessionStateSupport.setAttribute(name, value, req, resp);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerbero\\utils\AdapterSessionStateSupport.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */