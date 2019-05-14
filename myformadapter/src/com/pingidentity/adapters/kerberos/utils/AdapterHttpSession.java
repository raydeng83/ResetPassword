package com.pingidentity.adapters.kerberos.utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;




public class AdapterHttpSession
  implements AdapterSession
{
  public Object getAttribute(String name, HttpServletRequest req, HttpServletResponse resp)
  {
    HttpSession session = req.getSession();
    return session.getAttribute(name);
  }
  
  public Object removeAttribute(String name, HttpServletRequest req, HttpServletResponse resp)
  {
    HttpSession session = req.getSession();
    
    Object value = session.getAttribute(name);
    session.removeAttribute(name);
    
    return value;
  }
  
  public void setAttribute(String name, Object value, HttpServletRequest req, HttpServletResponse resp)
  {
    HttpSession session = req.getSession();
    session.setAttribute(name, value);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerbero\\utils\AdapterHttpSession.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */