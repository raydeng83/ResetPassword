package com.pingidentity.adapters.kerberos.utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract interface AdapterSession
{
  public abstract void setAttribute(String paramString, Object paramObject, HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse);
  
  public abstract Object getAttribute(String paramString, HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse);
  
  public abstract Object removeAttribute(String paramString, HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse);
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerbero\\utils\AdapterSession.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */