package com.pingidentity.adapters.htmlform.pwdchange.model;

import java.util.ArrayList;
import java.util.List;


public class IdentifyForm
{
  private boolean isSubmit;
  private String username;
  private String currentPassword;
  private String newPassword;
  private String confirmNewPassword;
  private List<String> errorList = new ArrayList();
  
  public String getUsername()
  {
    return this.username;
  }
  
  public void setUsername(String username)
  {
    this.username = username;
  }
  
  public List<String> getErrorList()
  {
    return this.errorList;
  }
  
  public void setErrorList(List<String> errorList)
  {
    this.errorList = errorList;
  }
  
  public String getCurrentPassword()
  {
    return this.currentPassword;
  }
  

  public void setCurrentPassword(String currentPassword)
  {
    this.currentPassword = currentPassword;
  }
  
  public String getNewPassword()
  {
    return this.newPassword;
  }
  
  public void setNewPassword(String newPassword)
  {
    this.newPassword = newPassword;
  }
  
  public String getConfirmNewPassword()
  {
    return this.confirmNewPassword;
  }
  
  public void setConfirmNewPassword(String confirmNewPassword)
  {
    this.confirmNewPassword = confirmNewPassword;
  }
  
  public boolean isSubmit()
  {
    return this.isSubmit;
  }
  
  public void setSubmit(boolean isSubmit)
  {
    this.isSubmit = isSubmit;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\htmlform\pwdchange\model\IdentifyForm.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */