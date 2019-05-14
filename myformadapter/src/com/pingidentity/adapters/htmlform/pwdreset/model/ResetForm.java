package com.pingidentity.adapters.htmlform.pwdreset.model;

import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;



public class ResetForm
  extends BaseForm
{
  private String newPassword;
  private String confirmPassword;
  private boolean isSubmit;
  
  public ResetForm(SessionStateUtil sessionUtil, HttpServletRequest request, HttpServletResponse response)
  {
    super(sessionUtil, request);
    parseRequest(request, response);
  }
  
  public boolean isSubmit() {
    return this.isSubmit;
  }
  
  public void setSubmit(boolean isSubmit) {
    this.isSubmit = isSubmit;
  }
  
  public String getNewPassword() {
    return this.newPassword;
  }
  
  public void setNewPassword(String newPassword) {
    this.newPassword = newPassword;
  }
  
  public String getConfirmPassword() {
    return this.confirmPassword;
  }
  
  public void setConfirmPassword(String confirmPassword) {
    this.confirmPassword = confirmPassword;
  }
  
  private void parseRequest(HttpServletRequest request, HttpServletResponse response) {
    loadSessionState(request, response);
    
    if ((request.getParameter("Password1") != null) && (!request.getParameter("Password1").isEmpty())) {
      setNewPassword(request.getParameter("Password1"));
    }
    if ((request.getParameter("Password2") != null) && (!request.getParameter("Password2").isEmpty())) {
      setConfirmPassword(request.getParameter("Password2"));
    }
    
    if (request.getParameter("Reset") != null)
    {
      if (request.getParameter("Reset").equals("clicked")) {
        setSubmit(true);
      } else {
        setSubmit(false);
      }
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\model\ResetForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */