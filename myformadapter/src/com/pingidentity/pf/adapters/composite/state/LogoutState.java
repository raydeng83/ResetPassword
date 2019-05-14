package com.pingidentity.pf.adapters.composite.state;

import java.io.Serializable;

public class LogoutState
  implements Serializable
{
  private static final long serialVersionUID = 1L;
  public int adapterIdx = 0;
  public int numSuccesses = 0;
  public boolean waitingAdapterResponse = false;
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\adapters\composite\state\LogoutState.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */