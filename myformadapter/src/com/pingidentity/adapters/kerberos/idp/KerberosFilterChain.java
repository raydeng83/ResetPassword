package com.pingidentity.adapters.kerberos.idp;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KerberosFilterChain
  implements FilterChain
{
  private static final Logger log = LogManager.getLogger(KerberosAuthenticationAdapter.class);
  
  public void doFilter(ServletRequest request, ServletResponse response)
  {
    HttpServletRequest httpServletRequest = (HttpServletRequest)request;
    log.debug("+ KerberosFilterChain.doFilter()");
    if (httpServletRequest.getRemoteUser() != null)
    {
      log.debug("httpServletResuest.getRemoteUser() = " + httpServletRequest.getRemoteUser());
      HttpSession httpSession = httpServletRequest.getSession();
      httpSession.setAttribute("REMOTE_USER", httpServletRequest.getRemoteUser());
    }
    log.debug("- KerberosFilterChain.doFilter()");
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerberos\idp\KerberosFilterChain.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */