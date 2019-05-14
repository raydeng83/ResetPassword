package com.pingidentity.pf.adapters.composite.state;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import org.sourceid.saml20.adapter.attribute.AttributeValue;


public class AllAttributesState
  implements Serializable
{
  private static final long serialVersionUID = 1L;
  public Map<String, Object> attributes = new HashMap();
  public Map<Integer, AttributeValue> authnCtx = new HashMap();
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\adapters\composite\state\AllAttributesState.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */