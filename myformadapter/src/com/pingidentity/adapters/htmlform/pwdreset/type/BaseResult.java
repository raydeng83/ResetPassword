package com.pingidentity.adapters.htmlform.pwdreset.type;

public enum BaseResult {
  Error, 
  








  CodeExpired, 
  








  Success, 
  








  TooManyAttempts, 
  








  InvalidCode;
  



  private BaseResult() {}
  



  public SecurityCodeResult asSecurityCodeResult()
  {
    return SecurityCodeResult.Error;
  }
  
  public ResetResult asResetResult() {
    return ResetResult.Error;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdreset\type\BaseResult.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */