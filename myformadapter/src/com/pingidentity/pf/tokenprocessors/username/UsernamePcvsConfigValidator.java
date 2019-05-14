package com.pingidentity.pf.tokenprocessors.username;

import java.util.List;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Row;
import org.sourceid.saml20.adapter.conf.Table;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;




















class UsernamePcvsConfigValidator
  implements ConfigurationValidator
{
  public void validate(Configuration configuration)
    throws ValidationException
  {
    Table pcvsTable = configuration.getTable("Credential Validators");
    List<Row> pcvRows = pcvsTable.getRows();
    if (pcvRows.isEmpty())
    {
      throw new ValidationException("Please add at least one password credential validator.");
    }
  }
}


/* Location:              D:\workhouse\PasswordReset\myformadapter\src\!\com\pingidentity\pf\tokenprocessor\\username\UsernamePcvsConfigValidator.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       0.7.1
 */