package com.pingidentity.pf.adapters.composite.validators;

import java.util.List;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

public class CompositeAdapterConfigurationValidator
  implements ConfigurationValidator
{
  public void validate(Configuration configuration)
    throws ValidationException
  {
    if (configuration.getTable("Adapters").getRows().size() == 0)
    {
      throw new ValidationException("You must add at least one adapter instance.");
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\adapters\composite\validators\CompositeAdapterConfigurationValidator.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */