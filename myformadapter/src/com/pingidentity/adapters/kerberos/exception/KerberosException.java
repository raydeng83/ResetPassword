package com.pingidentity.adapters.kerberos.exception;


public class KerberosException
  extends Exception
{
  private static final long serialVersionUID = 1L;
  private boolean kdcLoginProblem;
  private boolean tgsValidationProblem;
  
  public KerberosException(boolean kdcLoginProblem, boolean tgsValidationProblem)
  {
    this.kdcLoginProblem = kdcLoginProblem;
    this.tgsValidationProblem = tgsValidationProblem;
  }
  
  public KerberosException(String message, boolean kdcLoginProblem, boolean tgsValidationProblem)
  {
    super(message);
    this.kdcLoginProblem = kdcLoginProblem;
    this.tgsValidationProblem = tgsValidationProblem;
  }
  
  public KerberosException(String message, Throwable cause, boolean kdcLoginProblem, boolean tgsValidationProblem)
  {
    super(message, cause);
    this.kdcLoginProblem = kdcLoginProblem;
    this.tgsValidationProblem = tgsValidationProblem;
  }
  
  public KerberosException(Throwable cause, boolean kdcLoginProblem, boolean tgsValidationProblem)
  {
    super(cause);
    this.kdcLoginProblem = kdcLoginProblem;
    this.tgsValidationProblem = tgsValidationProblem;
  }
  
  public boolean isKdcLoginProblem()
  {
    return this.kdcLoginProblem;
  }
  
  public boolean isTgsValidationProblem()
  {
    return this.tgsValidationProblem;
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\adapters\kerberos\exception\KerberosException.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */