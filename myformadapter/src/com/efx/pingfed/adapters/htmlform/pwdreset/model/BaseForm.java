package com.efx.pingfed.adapters.htmlform.pwdreset.model;

import com.efx.pingfed.adapters.htmlform.pwdreset.util.SessionStateUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class BaseForm
{
  private String scheme;
  private String serverName;
  private int serverPort;
  private String username = null;
  private String targetResource = null;
  
  private SessionStateUtil sessionUtil;
  

  public BaseForm(SessionStateUtil sessionUtil, HttpServletRequest request)
  {
    this.sessionUtil = sessionUtil;
    parseRequest(request);
  }
  
  public String getUsername()
  {
    return this.username;
  }
  
  public void setUsername(String username) {
    this.username = username;
  }
  
  public String getTargetResource() {
    return this.targetResource;
  }
  
  public void setTargetResource(String targetResource) {
    this.targetResource = targetResource;
  }
  
  public String getRootPath()
  {
    StringBuilder path = new StringBuilder(this.scheme);
    path.append("://").append(this.serverName);
    if ((this.serverPort != 80) && (this.serverPort != 443)) {
      path.append(":").append(this.serverPort);
    }
    return path.toString();
  }
  
  protected void loadSessionState(HttpServletRequest request, HttpServletResponse response)
  {
    setUsername((String)this.sessionUtil.get("prUsername", request, response));
    setTargetResource((String)this.sessionUtil.get("prReferrer", request, response));
  }
  
  private void parseRequest(HttpServletRequest request)
  {
    this.scheme = request.getScheme();
    this.serverName = request.getServerName();
    this.serverPort = request.getServerPort();
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\model\BaseForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */