package com.efx.pingfed.adapters.htmlform.pwdreset.model;

import com.efx.pingfed.adapters.htmlform.pwdreset.util.SessionStateUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ResumeForm
  extends BaseForm
{
  private String referenceId;
  
  public ResumeForm(SessionStateUtil sessionUtil, HttpServletRequest request, HttpServletResponse response)
  {
    super(sessionUtil, request);
    parseRequest(request, response);
  }
  
  public String getReferenceId() {
    return this.referenceId;
  }
  
  public void setReferenceId(String referenceId) {
    this.referenceId = referenceId;
  }
  
  private void parseRequest(HttpServletRequest request, HttpServletResponse response) {
    loadSessionState(request, response);
    
    if ((request.getParameter("a") != null) && (!request.getParameter("a").isEmpty())) {
      setReferenceId(request.getParameter("a"));
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\model\ResumeForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */