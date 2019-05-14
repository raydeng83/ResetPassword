package com.pingidentity.adapters.htmlform.pwdreset.model;


public class UserInfo
{
  private GeneratedCode generatedCode;
  
  private String name;
  
  private String toAddress;
  private String referrer;
  private String username;
  private String referenceId;
  
  public UserInfo() {}
  
  public UserInfo(String name, String toAddress)
  {
    this.name = name;
    this.toAddress = toAddress;
  }
  
  public UserInfo(String name, String toAddress, String referenceId) {
    this.name = name;
    this.toAddress = toAddress;
    this.referenceId = referenceId;
  }
  
  public UserInfo(String name, String toAddress, GeneratedCode generatedCode) {
    this(name, toAddress);
    this.generatedCode = generatedCode;
  }
  
  public UserInfo(String name, String toAddress, GeneratedCode generatedCode, String username) {
    this(name, toAddress, generatedCode);
    this.username = username;
  }
  
  public UserInfo(String name, String toAddress, GeneratedCode generatedCode, String username, String referrer) {
    this(name, toAddress, generatedCode, username);
    this.referrer = referrer;
  }
  
  public GeneratedCode getGeneratedCode() {
    return this.generatedCode;
  }
  
  public void setGeneratedCode(GeneratedCode generatedCode) {
    this.generatedCode = generatedCode;
  }
  
  public String getName() {
    return this.name;
  }
  
  public void setName(String name) {
    this.name = name;
  }
  
  public String getToAddress() {
    return this.toAddress;
  }
  
  public void setToAddress(String toAddress) {
    this.toAddress = toAddress;
  }
  
  public String getReferrer() {
    return this.referrer;
  }
  
  public void setReferrer(String referrer) {
    this.referrer = referrer;
  }
  
  public String getUsername() {
    return this.username;
  }
  
  public void setUsername(String username) {
    this.username = username;
  }
  
  public String getReferenceId() {
    return this.referenceId;
  }
  
  public void setReferenceId(String referenceId) {
    this.referenceId = referenceId;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\model\UserInfo.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */