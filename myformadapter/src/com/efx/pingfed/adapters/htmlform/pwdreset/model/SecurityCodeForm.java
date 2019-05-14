package com.efx.pingfed.adapters.htmlform.pwdreset.model;

import com.efx.pingfed.adapters.htmlform.pwdreset.util.SessionStateUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class SecurityCodeForm
  extends BaseForm
{
  private String securityCode;
  private boolean isSubmit;
  
  public SecurityCodeForm(SessionStateUtil sessionUtil, HttpServletRequest request, HttpServletResponse response)
  {
    super(sessionUtil, request);
    parseRequest(request, response);
  }
  
  public String getSecurityCode() {
    return this.securityCode;
  }
  
  public void setSecurityCode(String securityCode) {
    this.securityCode = securityCode;
  }
  
  public boolean isSubmit() {
    return this.isSubmit;
  }
  
  public void setSubmit(boolean isSubmit) {
    this.isSubmit = isSubmit;
  }
  
  private void parseRequest(HttpServletRequest request, HttpServletResponse response) {
    loadSessionState(request, response);
    
    if ((request.getParameter("SecurityCode") != null) && (!request.getParameter("SecurityCode").isEmpty())) {
      setSecurityCode(request.getParameter("SecurityCode"));
    }
    
    if (request.getParameter("Change") != null) {
      if (request.getParameter("Change").equals("clicked")) {
        setSubmit(true);
      } else {
        setSubmit(false);
      }
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\model\SecurityCodeForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */