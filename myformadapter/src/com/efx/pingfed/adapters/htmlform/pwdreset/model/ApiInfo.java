package com.efx.pingfed.adapters.htmlform.pwdreset.model;

import org.json.simple.JSONObject;


public class ApiInfo
{
  private boolean isSuccess;
  private int responseCode;
  private String response;
  private JSONObject payload;
  private long errorId;
  private String errorMessage;
  private String messageId;
  private String sessionId;
  
  public boolean isSuccess()
  {
    return this.isSuccess;
  }
  
  public void setSuccess(boolean isSuccess) { this.isSuccess = isSuccess; }
  
  public int getResponseCode() {
    return this.responseCode;
  }
  
  public void setResponseCode(int responseCode) { this.responseCode = responseCode; }
  
  public String getResponse() {
    return this.response;
  }
  
  public void setResponse(String response) { this.response = response; }
  
  public JSONObject getPayload() {
    return this.payload;
  }
  
  public void setPayload(JSONObject payload) { this.payload = payload; }
  
  public long getErrorId() {
    return this.errorId;
  }
  
  public void setErrorId(long errorId) { this.errorId = errorId; }
  
  public String getErrorMessage() {
    return this.errorMessage;
  }
  
  public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
  
  public String getMessageId() {
    return this.messageId;
  }
  
  public void setMessageId(String messageId) { this.messageId = messageId; }
  
  public String getSessionId() {
    return this.sessionId;
  }
  
  public void setSessionId(String sessionId) { this.sessionId = sessionId; }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\model\ApiInfo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */