package com.efx.pingfed.adapters.htmlform.session;

import org.sourceid.saml20.adapter.state.SessionStateSupport;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class HtmlFormSessionStateSupport
  extends SessionStateSupport
{
  public void refreshSession(String key, HttpServletRequest req, HttpServletResponse resp)
  {
    setAttribute(key, Long.valueOf(System.currentTimeMillis()), req, resp, false);
  }
  
  public void setInactivityTimeout(String key, int timeout, HttpServletRequest req, HttpServletResponse resp)
  {
    setAttribute(key, Integer.valueOf(timeout), req, resp, false);
  }
  
  public Integer getInactivityTimeout(String key, HttpServletRequest req, HttpServletResponse resp)
  {
    return (Integer)getAttribute(key, req, resp);
  }
  

  public boolean isSessionExpired(String lastActivityKey, Integer inactivityTimeout, HttpServletRequest req, HttpServletResponse resp)
  {
    if (inactivityTimeout == null)
    {

      return false;
    }
    
    long currentTime = System.currentTimeMillis();
    Long lastActivity = (Long)getAttribute(lastActivityKey, req, resp);
    
    if (lastActivity == null)
    {
      return true;
    }
    
    if (lastActivity.longValue() + inactivityTimeout.intValue() * 1000 * 60 > currentTime)
    {
      return false;
    }
    

    return true;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\session\HtmlFormSessionStateSupport.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */