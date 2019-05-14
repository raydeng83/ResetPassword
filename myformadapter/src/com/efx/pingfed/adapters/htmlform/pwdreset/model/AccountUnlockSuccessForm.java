package com.efx.pingfed.adapters.htmlform.pwdreset.model;

import com.efx.pingfed.adapters.htmlform.pwdreset.util.SessionStateUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class AccountUnlockSuccessForm
  extends BaseForm
{
  private boolean isContinue = false;
  private boolean isReset = false;
  
  public AccountUnlockSuccessForm(SessionStateUtil sessionUtil, HttpServletRequest request, HttpServletResponse response)
  {
    super(sessionUtil, request);
    parseRequest(request, response);
  }
  
  public boolean isContinue()
  {
    return this.isContinue;
  }
  
  public void setContinue(boolean isContinue)
  {
    this.isContinue = isContinue;
  }
  
  public boolean isReset()
  {
    return this.isReset;
  }
  
  public void setReset(boolean isReset)
  {
    this.isReset = isReset;
  }
  
  private void parseRequest(HttpServletRequest request, HttpServletResponse response)
  {
    loadSessionState(request, response);
    boolean continueClicked = "clicked".equals(request.getParameter("Unlock"));
    setContinue(continueClicked);
    
    if (!continueClicked)
    {
      boolean resetClicked = "clicked".equals(request.getParameter("Reset"));
      setReset(resetClicked);
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\model\AccountUnlockSuccessForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */