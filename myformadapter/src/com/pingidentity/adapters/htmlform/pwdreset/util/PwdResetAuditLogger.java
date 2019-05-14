package com.pingidentity.adapters.htmlform.pwdreset.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.ThreadContext;
import org.sourceid.util.log.internal.TrackingIdSupport;
import org.sourceid.websso.AuditLogger.MDC_KEY;
import org.sourceid.websso.profiles.idp.IdpAuditLogger;






public class PwdResetAuditLogger
  extends IdpAuditLogger
{
  public static final String PWD_RESET_REQUEST = "PWD_RESET_REQUEST";
  public static final String PWD_RESET_REQUEST_RESPONSE = "PWD_RESET_REQUEST_RESPONSE";
  public static final String PWD_RESET = "PWD_RESET";
  public static final String ACCOUNT_UNLOCK = "ACCOUNT_UNLOCK";
  public static final String PWD_CHANGE = "PWD_CHANGE";
  
  public static void init(String event, HttpServletRequest request, HttpServletResponse response)
  {
    ThreadContext.put("trackingid", TrackingIdSupport.generateTrackingId(request, response));
    
    IdpAuditLogger.init();
    
    if (request.getAttribute("com.pingidentity.appserver.REQUEST_TIMESTAMP") != null) {
      IdpAuditLogger.setRequestStartTime((Long)request.getAttribute("com.pingidentity.appserver.REQUEST_TIMESTAMP"));
    }
    
    IdpAuditLogger.setRemoteAddress(request.getRemoteAddr());
    IdpAuditLogger.setEvent(event);
  }
  



  public static void log()
  {
    ThreadContext.put(AuditLogger.MDC_KEY.DESCRIPTION.toString(), "");
    
    IdpAuditLogger.log("");
  }
  


  public static void logFailure()
  {
    logFailure(null);
  }
  




  public static void logFailure(String description)
  {
    IdpAuditLogger.setStatus("failure");
    IdpAuditLogger.setDescription(description);
    IdpAuditLogger.log("");
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdrese\\util\PwdResetAuditLogger.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */