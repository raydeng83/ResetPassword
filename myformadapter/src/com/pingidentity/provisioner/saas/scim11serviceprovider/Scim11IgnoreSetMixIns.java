package com.pingidentity.provisioner.saas.scim11serviceprovider;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class Scim11IgnoreSetMixIns
{
  @JsonIgnore
  public abstract Boolean getActive();
  
  @JsonProperty
  public abstract boolean isActive();
  
  @JsonProperty
  public abstract void setActive(Boolean paramBoolean);
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\provisioner\saas\scim11serviceprovider\Scim11IgnoreSetMixIns.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */