package com.pingidentity.adapters.htmlform.idrecovery.model;

import com.pingidentity.adapters.htmlform.pwdreset.model.BaseForm;
import com.pingidentity.adapters.htmlform.pwdreset.util.SessionStateUtil;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RecoverUsernameForm
  extends BaseForm
{
  private boolean isSubmit;
  private String email;
  
  public RecoverUsernameForm(SessionStateUtil sessionUtil, HttpServletRequest request, HttpServletResponse response)
  {
    super(sessionUtil, request);
    
    loadSessionState(request, response);
  }
  
  public boolean isSubmit()
  {
    return this.isSubmit;
  }
  
  public void setSubmit(boolean isSubmit)
  {
    this.isSubmit = isSubmit;
  }
  
  public String getEmail()
  {
    return this.email;
  }
  
  public void setEmail(String email)
  {
    this.email = email;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\idrecovery\model\RecoverUsernameForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */