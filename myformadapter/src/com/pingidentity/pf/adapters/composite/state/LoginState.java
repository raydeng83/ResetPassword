package com.pingidentity.pf.adapters.composite.state;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class LoginState
  implements Serializable
{
  private static final long serialVersionUID = 1L;
  public int adapterIdx = 0;
  public Map<String, Object> attributes = new HashMap();
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\adapters\composite\state\LoginState.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */