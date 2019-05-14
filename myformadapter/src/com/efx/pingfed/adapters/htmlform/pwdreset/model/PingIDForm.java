package com.efx.pingfed.adapters.htmlform.pwdreset.model;

import com.efx.pingfed.adapters.htmlform.pwdreset.util.SessionStateUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class PingIDForm
  extends BaseForm
{
  private String ppmResponse;
  
  public PingIDForm(SessionStateUtil sessionUtil, HttpServletRequest request, HttpServletResponse response)
  {
    super(sessionUtil, request);
    parseRequest(request, response);
  }
  
  public String getPpmResponse() {
    return this.ppmResponse;
  }
  
  public void setPpmResponse(String ppmResponse) {
    this.ppmResponse = ppmResponse;
  }
  
  private void parseRequest(HttpServletRequest request, HttpServletResponse response) {
    loadSessionState(request, response);
    
    if ((request.getParameter("ppm_response") != null) && (!request.getParameter("ppm_response").isEmpty())) {
      setPpmResponse(request.getParameter("ppm_response"));
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\model\PingIDForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */