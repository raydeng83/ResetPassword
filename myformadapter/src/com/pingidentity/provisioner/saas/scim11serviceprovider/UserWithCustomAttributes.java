package com.pingidentity.provisioner.saas.scim11serviceprovider;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import java.util.HashMap;
import java.util.Map;
import scim.schemas.core.v1.User;

public class UserWithCustomAttributes extends User
{
  @com.fasterxml.jackson.annotation.JsonIgnore
  @org.codehaus.jackson.annotate.JsonIgnore
  private Map<String, Object> customAttributes = new HashMap();
  
  public UserWithCustomAttributes(UserWithCustomAttributes user) {
    super(user);
    this.schemas = user.schemas;
    this.customAttributes = user.getAnyAttributes();
  }
  

  public UserWithCustomAttributes() {}
  
  @JsonAnyGetter
  public Map<String, Object> getAnyAttributes()
  {
    return this.customAttributes;
  }
  
  @com.fasterxml.jackson.annotation.JsonAnySetter
  public void setAnyAttributes(String name, Object value)
  {
    this.customAttributes.put(name, value);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\provisioner\saas\scim11serviceprovider\UserWithCustomAttributes.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */