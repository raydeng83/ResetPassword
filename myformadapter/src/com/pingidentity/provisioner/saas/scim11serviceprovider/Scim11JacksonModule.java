package com.pingidentity.provisioner.saas.scim11serviceprovider;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.Module.SetupContext;
import com.fasterxml.jackson.databind.module.SimpleModule;
import scim.schemas.core.v1.User;

public class Scim11JacksonModule
  extends SimpleModule
{
  public Scim11JacksonModule()
  {
    super("Scim11JacksonModule", new Version(0, 0, 1, null, null, null));
  }
  

  public void setupModule(Module.SetupContext context)
  {
    context.setMixInAnnotations(User.class, Scim11IgnoreSetMixIns.class);
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\provisioner\saas\scim11serviceprovider\Scim11JacksonModule.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */