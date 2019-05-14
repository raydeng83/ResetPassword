package com.efx.pingfed.adapters.htmlform.pwdreset.model;

import com.efx.pingfed.adapters.htmlform.pwdreset.util.SessionStateUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class IdentifyForm
  extends BaseForm
{
  private boolean isSubmit;
  
  public IdentifyForm(SessionStateUtil sessionUtil, HttpServletRequest request, HttpServletResponse response)
  {
    super(sessionUtil, request);
    
    loadSessionState(request, response);
  }
  
  public boolean isSubmit() {
    return this.isSubmit;
  }
  
  public void setSubmit(boolean isSubmit) {
    this.isSubmit = isSubmit;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\model\IdentifyForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */